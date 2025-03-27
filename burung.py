#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import base64
import argparse
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from dotenv import load_dotenv

def encrypt_value(value, key=None):
    """Encrypt a value for .env file compatible with PHP decrypt_env function"""
    # Load environment variables
    load_dotenv()
    
    # Get encryption key
    if key is None:
        key = os.environ.get('ENCRYPTION_KEY', 'default-encryption-key')
    
    # Ensure key is correct length for AES-256 (32 bytes)
    key = key.ljust(32)[:32].encode('utf-8')
    
    # Generate random IV
    backend = default_backend()
    iv = os.urandom(16)  # AES block size is 16 bytes for AES-256-CBC
    
    # Create encryptor
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    
    # Pad the value to be a multiple of block size
    block_size = 16
    padding = block_size - (len(value) % block_size)
    padded_value = value + chr(padding) * padding
    
    # Encrypt the value
    encrypted_value = encryptor.update(padded_value.encode('utf-8')) + encryptor.finalize()
    
    # Combine IV and encrypted value and encode as base64
    combined = iv + encrypted_value
    encoded = base64.b64encode(combined).decode('utf-8')
    
    return f"ENC:{encoded}"

def main():
    parser = argparse.ArgumentParser(description='Encrypt values for .env file')
    parser.add_argument('value', help='Value to encrypt')
    parser.add_argument('-k', '--key', help='Override encryption key')
    
    args = parser.parse_args()
    
    if not args.value:
        print("Error: No value provided for encryption")
        parser.print_help()
        sys.exit(1)
    
    encrypted = encrypt_value(args.value, args.key)
    
    print(f"Original: {args.value}")
    print(f"Encrypted: {encrypted}")
    print("Masukkan nilai ini ke file .env anda")

if __name__ == "__main__":
    main()