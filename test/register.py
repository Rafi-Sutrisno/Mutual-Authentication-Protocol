import requests
import uuid
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

BASE = "http://127.0.0.1:8000"
client_id = "fails_client"

def get_mac_address():
    """Get this machine's primary MAC address in aa:bb:cc:dd:ee:ff format."""
    mac = uuid.getnode()
    return ':'.join([f'{(mac >> ele) & 0xff:02x}' for ele in range(40, -1, -8)])

# 1. Generate RSA key pair for the client
print("▶ Generating RSA key pair...")
client_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
client_public_key = client_private_key.public_key()

# Save the private key locally so the same client can re-authenticate later
with open(f"{client_id}_private.pem", "wb") as f:
    f.write(
        client_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    )

# 2. Create a new client entry on the server (if not already exists)
print("\n▶ Creating new client...")
r = requests.post(f"{BASE}/auth/new_client", json={"client_id": client_id})
print("Response:", r.json())

# 3. Upload public key + MAC address to the server
pem = client_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode()

client_mac = get_mac_address()
print(f"\n▶ Registering public key with MAC {client_mac}...")
r = requests.post(f"{BASE}/auth/register", json={
    "client_id": client_id,
    "public_key_pem": pem,
    "mac": client_mac
})
print("Response:", r.json())

print(f"\n✅ Client {client_id} registered with MAC {client_mac}. Private key saved to {client_id}_private.pem")
