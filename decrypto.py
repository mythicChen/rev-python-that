# RansomwareX Analysis and Decryption Tool
# Author: Alex Chen
# Last Modified: 2025-03-18
# Status: Work in Progress - DO NOT SHARE

import base64
import hashlib
import os
import sys
import struct
import requests
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Configuration constants
C2_PATTERNS = [
    r"hxxp[s]?://(\d{1,3}\.){3}\d{1,3}:([0-9]{2,5})/gate\.php",
    r"hxxp[s]?://[a-zA-Z0-9\-\.]+\.onion/[a-zA-Z0-9]{8}",
    r"185\.212\.47\.\d{1,3}",
    r"pjqvs6[a-zA-Z0-9]{5,10}\.onion"
]

# XOR key obtained from memory dump
XOR_KEY = b"\x7A\x3E\x15\x8C\xAA\x59\xC3\x78"

# Decryption method patterns
DECRYPTION_METHODS = {
    "v1": "AES-256-CBC",
    "v2": "ChaCha20",
    "v3": "Custom XOR + RC4",
    "v4": "AES-256-GCM"
}

# RSA public key modulus extracted from binary (partial)
RSA_MODULUS = """
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvXEbJ5A8ZX1UImDZXIyJ
tPMZ8Ob3KU4epDZQFH8CprDoTQZC1jQfQKP8j1TUy33AAk0bjgKzojfQkGFJUPZF
VpLR9FO03vMIFyCgvWm0da2K2h4NXzxB8rWmfOZHW1nKBmyJqPzJ7MhB8A9ZNyJK
x0EXmLVRWZyEIuWdIgVbVPuRJxwqFHHrHCVqYYCKYgQIjlcbULj1zJSP3zYXOnPA
"""

def xor_buffer(data, key):
    """XOR buffer with repeating key"""
    key_len = len(key)
    return bytes(data[i] ^ key[i % key_len] for i in range(len(data)))

def extract_key_from_memory_dump(dump_path):
    """Extract encryption key from memory dump file"""
    try:
        with open(dump_path, "rb") as f:
            dump_data = f.read()
        
        # Look for specific pattern preceding the key
        pattern = b"\x3C\xAF\xFE\xBA\xBE"
        pattern_pos = dump_data.find(pattern)
        
        if pattern_pos == -1:
            print("[!] Error: Key pattern not found in memory dump")
            return None
        
        # Extract 32 bytes after pattern + 4 offset
        raw_key = dump_data[pattern_pos + len(pattern) + 4:pattern_pos + len(pattern) + 36]
        
        # Decode key with XOR
        final_key = xor_buffer(raw_key, XOR_KEY)
        
        print(f"[+] Successfully extracted key: {final_key.hex()}")
        return final_key
    
    except Exception as e:
        print(f"[!] Error extracting key: {str(e)}")
        return None

def check_for_vulnerable_version(binary_path):
    """Check if ransomware version is vulnerable to key recovery"""
    try:
        with open(binary_path, "rb") as f:
            binary_data = f.read()
        
        # Check for version strings
        version_markers = {
            b"RansomX-v1.03b": False,
            b"RansomX-v1.04a": False, 
            b"RansomX-v1.05c": True,
            b"RansomX-v1.06": True,
            b"RansomX-v2.0": False
        }
        
        for marker, is_vulnerable in version_markers.items():
            if marker in binary_data:
                print(f"[+] Identified version: {marker.decode('utf-8')}")
                return is_vulnerable
                
        print("[!] Could not identify version - assuming not vulnerable")
        return False
        
    except Exception as e:
        print(f"[!] Error checking binary: {str(e)}")
        return False

def brute_force_key_seed(encrypted_file, known_header, max_seed=10000):
    """Attempt to brute force the key seed if it's within range"""
    print(f"[*] Attempting to brute force key seed (0-{max_seed})...")
    
    try:
        with open(encrypted_file, "rb") as f:
            enc_data = f.read(len(known_header) + 16)  # Header + IV
        
        # Extract IV (first 16 bytes)
        iv = enc_data[:16]
        encrypted_header = enc_data[16:16+len(known_header)]
        
        for seed in range(max_seed):
            # Generate key from seed
            key_material = hashlib.sha256(struct.pack("<I", seed)).digest()
            
            # Try to decrypt
            cipher = Cipher(algorithms.AES(key_material), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted = decryptor.update(encrypted_header) + decryptor.finalize()
            
            if decrypted.startswith(known_header):
                print(f"[+] Found working seed: {seed}")
                return key_material
            
            if seed % 1000 == 0:
                print(f"[*] Tried {seed} seeds...")
        
        print("[!] Could not find working seed")
        return None
        
    except Exception as e:
        print(f"[!] Error during brute force: {str(e)}")
        return None

def decrypt_file(encrypted_file, output_file, key, version="v1"):
    """Decrypt a file using the appropriate method for the version"""
    try:
        with open(encrypted_file, "rb") as f:
            data = f.read()
        
        # First 16 bytes is IV
        iv = data[:16]
        ciphertext = data[16:]
        
        if version == "v1" or version == "v4":
            # AES decryption
            mode = modes.CBC if version == "v1" else modes.GCM
            cipher = Cipher(algorithms.AES(key), mode(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
        elif version == "v2":
            # ChaCha20
            algorithm = algorithms.ChaCha20(key, iv)
            cipher = Cipher(algorithm, mode=None, backend=default_backend())
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
        elif version == "v3":
            # Custom XOR + RC4
            # TODO: Implement RC4 properly
            xor_result = xor_buffer(ciphertext, key)
            plaintext = xor_result  # Placeholder for full implementation
            
        else:
            print(f"[!] Unknown version: {version}")
            return False
        
        with open(output_file, "wb") as f:
            f.write(plaintext)
            
        print(f"[+] Successfully decrypted to {output_file}")
        return True
        
    except Exception as e:
        print(f"[!] Decryption error: {str(e)}")
        return False

def main():
    print("=" * 60)
    print("RansomwareX Analysis and Decryption Tool")
    print("=" * 60)
    print("WARNING: Work in Progress - For research purposes only")
    print("=" * 60)
    
    if len(sys.argv) < 3:
        print("Usage: python ransomware_analysis.py <command> <file_path> [options]")
        print("\nCommands:")
        print("  analyze    - Analyze ransomware binary")
        print("  extract    - Extract key from memory dump")
        print("  decrypt    - Decrypt a file using extracted key")
        print("  bruteforce - Attempt to brute force the key seed")
        return
    
    command = sys.argv[1]
    file_path = sys.argv[2]
    
    if command == "analyze":
        vulnerable = check_for_vulnerable_version(file_path)
        if vulnerable:
            print("[+] This version is vulnerable to key recovery techniques")
        else:
            print("[!] This version is not vulnerable to known techniques")
            
    elif command == "extract":
        key = extract_key_from_memory_dump(file_path)
        if key:
            # Save key to file
            with open("extracted_key.bin", "wb") as f:
                f.write(key)
            print(f"[+] Key saved to extracted_key.bin")
            
    elif command == "decrypt":
        if len(sys.argv) < 5:
            print("[!] Usage: python ransomware_analysis.py decrypt <encrypted_file> <key_file> <output_file> [version]")
            return
            
        key_file = sys.argv[3]
        output_file = sys.argv[4]
        version = sys.argv[5] if len(sys.argv) > 5 else "v1"
        
        with open(key_file, "rb") as f:
            key = f.read()
            
        decrypt_file(file_path, output_file, key, version)
        
    elif command == "bruteforce":
        if len(sys.argv) < 4:
            print("[!] Usage: python ransomware_analysis.py bruteforce <encrypted_file> <known_header_hex>")
            return
            
        known_header_hex = sys.argv[3]
        known_header = bytes.fromhex(known_header_hex)
        
        key = brute_force_key_seed(file_path, known_header)
        if key:
            with open("recovered_key.bin", "wb") as f:
                f.write(key)
            print(f"[+] Key saved to recovered_key.bin")
    
    else:
        print(f"[!] Unknown command: {command}")
        
if __name__ == "__main__":
    main()

# Notes to self:
# - The sample from ticket #4872 uses method v3 which is only partially implemented
# - Need to check with team about the RSA key extraction approach
# - The C2 domain crbE4n30sjG.onion appears to be offline as of yesterday
# - TODO: Add key file format from latest samples
# - Key hash observed: 7febcff21def485e2d9c3b4fe0ae8912aa1b02cc087548aefda0cebfaba96037
# 
# For decryption tool release:
# - Remove debug output
# - Add batch processing
# - Improve error handling
# - Make version detection automatic
# 
# Update from yesterday's team meeting:
# - Sample 8f9a22ebc22c33a66a0b8fa280b47a661e5bb7fc29bba23a1b48458cbb520a0c
#   appears to be a development build with debug symbols!
#   Check the "old_implementations" folder for a possible script to extract these
