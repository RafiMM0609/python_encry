#!/usr/bin/env python3

import os
import sys
from dotenv import load_dotenv

def encrypt_value(value, key=None):
    """Encrypt a value using simple XOR"""
    # Load environment variables
    load_dotenv()
    
    # Get encryption key
    if key is None:
        key = os.environ.get('ENCRYPTION_KEY', 'default-encryption-key')
    
    # Ensure we have a key
    if not key:
        raise ValueError("Encryption key is required")
    
    # XOR encryption
    key_bytes = key.encode('utf-8')
    value_bytes = value.encode('utf-8')
    key_len = len(key_bytes)
    
    # Perform XOR operation
    encrypted = []
    for i in range(len(value_bytes)):
        encrypted.append(value_bytes[i] ^ key_bytes[i % key_len])
    
    # Convert to hex string for safe storage in .env
    hex_result = ''.join([f"{b:02x}" for b in encrypted])
    return f"ENC_XOR:{hex_result}"

def main():
    if len(sys.argv) < 2:
        print("Usage: python encrypt_env_xor.py <value_to_encrypt>")
        sys.exit(1)
    
    value = sys.argv[1]
    encrypted = encrypt_value(value)
    
    print(f"Original: {value}")
    print(f"Encrypted: {encrypted}")
    print("Masukkan nilai ini ke file .env anda")

if __name__ == "__main__":
    main()