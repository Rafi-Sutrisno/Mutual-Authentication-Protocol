# benchmark/common_utils.py

import base64
import os
import uuid
import time
import secrets
import hashlib
import hmac
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

SERVER_PUF_SECRET = b"PUF_SIMULATION_KEY_123"

# --- Key Generation ---
def generate_key_pair():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = priv.public_key()
    return priv, pub

# --- RSA ---
def rsa_encrypt(pub, plaintext: bytes):
    return pub.encrypt(plaintext, padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    ))

def rsa_decrypt(priv, ciphertext: bytes):
    return priv.decrypt(ciphertext, padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    ))

def rsa_sign(priv, message: bytes):
    return priv.sign(message, padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

def rsa_verify(pub, message: bytes, signature: bytes):
    pub.verify(signature, message, padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

# --- AES ---
def normalize_key(key: bytes) -> bytes:
    return hashlib.sha256(key).digest()

def aes_encrypt(key: bytes, plaintext: bytes):
    key = normalize_key(key)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    return iv, encryptor.update(plaintext) + encryptor.finalize()

def aes_decrypt(key: bytes, iv: bytes, ciphertext: bytes):
    key = normalize_key(key)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# --- PUF ---
def simulate_puf(x: bytes, mac: str = None) -> bytes:
    if mac is None:
        mac = get_mac_address()
    mac_norm = mac.replace(":", "").replace("-", "").lower().encode()
    return hmac.new(SERVER_PUF_SECRET, mac_norm + x, hashlib.sha256).digest()

# --- Others ---
def F(x: bytes) -> bytes:
    return hashlib.sha256(x).digest()

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def generate_nonce(length=16) -> bytes:
    return secrets.token_bytes(length)

def get_mac_address() -> str:
    mac = uuid.getnode()
    return ':'.join([f'{(mac >> ele) & 0xff:02x}' for ele in range(40, -1, -8)])
