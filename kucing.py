from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

def encrypt(data, key):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(data.encode('utf-8'))
    return base64.b64encode(nonce + tag + ciphertext).decode('utf-8')

# key = get_random_bytes(16)  # Kunci harus 16, 24, atau 32 byte
key = b'ThisIsAFixedKey!'  # Constant key of 16 bytes
data = "bocahe.solutiontech.id"
encrypted_data = encrypt(data, key)
print(f"Encrypted: {encrypted_data}")
print(f"Key: {base64.b64encode(key).decode('utf-8')}")