import requests
import base64
import time
import uuid
from pathlib import Path
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

BASE = "http://127.0.0.1:8000"
client_id = "client1" 

# --- MAC detection ---
def get_mac_address():
    """Get this machine's primary MAC address in aa:bb:cc:dd:ee:ff format."""
    mac = uuid.getnode()
    return ':0'.join([f'{(mac >> ele) & 0xff:02x}' for ele in range(40, -1, -8)])

client_mac = get_mac_address()
print(f"▶ Using MAC address: {client_mac}")

# --- Load private key saved during registration (PEM) ---
priv_path = Path(f"{client_id}_private.pem")
if not priv_path.exists():
    raise SystemExit(f"Private key file not found: {priv_path}")

with open(priv_path, "rb") as f:
    client_private_key = serialization.load_pem_private_key(f.read(), password=None)

print(f"▶ Loaded private key for {client_id}")

# --- Helper functions ---
def rsa_decrypt_private(enc_bytes):
    return client_private_key.decrypt(
        enc_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_sign(data: bytes) -> bytes:
    return client_private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

# 1. Server verification
print("\n▶ Requesting server verification...")
r = requests.post(f"{BASE}/auth/server", json={"client_id": client_id})
print("Response:", r.json())

# 2. Client verification
print("\n▶ Sending client verification...")
r = requests.post(f"{BASE}/auth/client", json={"client_id": client_id})
print("Response:", r.json())

# 3. Mutual auth (server sends encrypted M4, M5)
print("\n▶ Starting mutual authentication...")
r = requests.post(f"{BASE}/auth/mutual", json={
    "client_id": client_id,
    "mac": client_mac
})
res = r.json()
print("Mutual Auth Response:", res)

if "M4" not in res or "M5" not in res:
    print("❌ Mutual authentication failed or missing M4/M5.")
    raise SystemExit(1)

# 4. Decrypt M4 and M5
m4_plain = rsa_decrypt_private(base64.b64decode(res["M4"]))
m5_plain = rsa_decrypt_private(base64.b64decode(res["M5"]))

if len(m4_plain) < 8 or len(m5_plain) < 8:
    print("❌ Malformed decrypted payloads")
    raise SystemExit(1)

A, B = m4_plain[:-8], m5_plain[:-8]
t4_bytes = m4_plain[-8:]
t4 = int.from_bytes(t4_bytes, 'big')
now = int(time.time())
if abs(now - t4) > 60:
    print(f"⚠️ Warning: timestamp t4 not recent (t4={t4}, now={now})")

# 5. Sign A||B
sig_b64 = base64.b64encode(rsa_sign(A + B)).decode()

# 6. Send verification (include MAC implicitly via server’s stored record)
print("\n▶ Sending M4 and M5 for verification (with signature)...")
r = requests.post(f"{BASE}/auth/verify", json={
    "client_id": client_id,
    "M4": base64.b64encode(m4_plain).decode(),
    "M5": base64.b64encode(m5_plain).decode(),
    "signature": sig_b64,
    "mac": client_mac
})
verify_res = r.json()
print("Final Auth Response:", verify_res)

if "session_token" not in verify_res or "session_id" not in verify_res:
    print("❌ No session token/session id received, authentication failed.")
    raise SystemExit(1)

session_token, session_id = verify_res["session_token"], verify_res["session_id"]
print("▶ Got session token:", session_token)
print("▶ Got session id:", session_id)

# 7. Use calculator API with Authorization header + session_id
print("\n▶ Testing Calculator API (protected)...")
payload = {
    "client_id": client_id,
    "values": [10, 20, 30],
    "operation": "sum",
    "session_id": session_id
}
headers = {"Authorization": f"Bearer {session_token}"}
r = requests.post(f"{BASE}/calc/calculate", json=payload, headers=headers)
print("Calculator Response:", r.json())
