#!/usr/bin/env python3

import os
import sys
import hashlib
import binascii
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from dotenv import load_dotenv

def encrypt_value(value, password=None, salt=None):
    """Encrypt value using AES-256-CBC with IV and salt"""
    # Load environment variables
    load_dotenv()
    
    # Get password from env or use provided one
    if password is None:
        password = os.environ.get('ENCRYPTION_KEY', 'default-key')
    
    # Generate random salt if not provided
    if salt is None:
        salt = os.urandom(16)
    elif isinstance(salt, str):
        salt = salt.encode('utf-8')
    
    # Derive key from password and salt
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 10000, 32)
    
    # Generate IV
    iv = os.urandom(16)
    
    # Create cipher
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    
    # Pad data (PKCS7)
    block_size = 16
    padding = block_size - (len(value) % block_size)
    padded_value = value + chr(padding) * padding
    
    # Encrypt
    encrypted = encryptor.update(padded_value.encode('utf-8')) + encryptor.finalize()
    
    # Format as hex: salt + iv + ciphertext
    result = binascii.hexlify(salt + iv + encrypted).decode('ascii')
    return f"AES256:{result}"

def main():
    if len(sys.argv) < 2:
        print("Usage: python encrypt_env_aes.py <value_to_encrypt> [salt]")
        sys.exit(1)
    
    value = sys.argv[1]
    salt = sys.argv[2] if len(sys.argv) > 2 else None
    
    encrypted = encrypt_value(value, salt=salt)
    
    print(f"Nilai Asli: {value}")
    print(f"Terenkripsi: {encrypted}")
    print("Salin nilai ini ke file .env Anda")

if __name__ == "__main__":
    main()