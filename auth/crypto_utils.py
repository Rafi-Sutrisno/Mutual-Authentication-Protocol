import hashlib
import os
import secrets
import uuid
import hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

SERVER_PUF_SECRET = b"PUF_SIMULATION_KEY_123"

def normalize_key(key: bytes) -> bytes:
    """Normalize any key material to 32 bytes (AES-256)."""
    return hashlib.sha256(key).digest()

def hash_sid(sid: str) -> bytes:
    return hashlib.sha256(sid.encode()).digest()

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def F(x: bytes) -> bytes:
    return hashlib.sha256(x).digest()

def get_mac_address() -> str:
    """Get this machine's primary MAC address in aa:bb:cc:dd:ee:ff format."""
    mac = uuid.getnode()
    return ':'.join([f'{(mac >> ele) & 0xff:02x}' for ele in range(40, -1, -8)])

def simulate_puf(x: bytes, mac: str = None) -> bytes:
    """
    Simulated PUF using client MAC address + nonce + server secret.
    - x: usually a nonce (bytes)
    - mac: optional MAC (string), auto-detected if not provided
    """
    if mac is None:
        mac = get_mac_address()
    mac_norm = mac.replace(":", "").replace("-", "").lower().encode()
    return hmac.new(SERVER_PUF_SECRET, mac_norm + x, hashlib.sha256).digest()

def generate_nonce(length=16) -> bytes:
    return secrets.token_bytes(length)

def aes_encrypt(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    key = normalize_key(key)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    return iv, encryptor.update(plaintext) + encryptor.finalize()

def aes_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    key = normalize_key(key)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()
