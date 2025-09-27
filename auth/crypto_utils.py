import hashlib
import hmac
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# --- Byte-level XOR ---
def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

# --- Derive function F (SHA-256 based) ---
def F(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

# --- Simulate a PUF using a keyed HMAC based on MAC address ---
def simulate_puf(input_bytes: bytes, mac_address: str) -> bytes:
    """
    Simulates a PUF output using the MAC address as key for HMAC.
    """
    mac_clean = mac_address.replace(':', '').lower()
    mac_bytes = bytes.fromhex(mac_clean)
    return hmac.new(mac_bytes, input_bytes, hashlib.sha256).digest()

# --- Generate secure random nonce ---
def generate_nonce(length: int = 16) -> bytes:
    return os.urandom(length)

# --- Hash the server ID ---
def hash_sid(server_id: str) -> bytes:
    return hashlib.sha256(server_id.encode()).digest()

# --- AES-CBC encryption ---
def aes_encrypt(key: bytes, plaintext: bytes) -> (bytes, bytes):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded = pad(plaintext)
    return iv, encryptor.update(padded) + encryptor.finalize()

# --- AES-CBC decryption ---
def aes_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    return unpad(padded)

# --- Padding (PKCS7) ---
def pad(data: bytes, block_size: int = 16) -> bytes:
    padding_len = block_size - len(data) % block_size
    return data + bytes([padding_len] * padding_len)

def unpad(padded: bytes) -> bytes:
    padding_len = padded[-1]
    if padding_len > len(padded):
        raise ValueError("Invalid padding")
    return padded[:-padding_len]
