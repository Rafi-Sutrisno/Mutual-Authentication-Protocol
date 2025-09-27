import requests
import base64
import time
import uuid
import csv
import tracemalloc
from pathlib import Path
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

BASE = "http://127.0.0.1:8000"
client_id = "client1"
RUNS = 100

def get_mac_address():
    mac = uuid.getnode()
    return ':'.join([f'{(mac >> ele) & 0xff:02x}' for ele in range(40, -1, -8)])

client_mac = get_mac_address()

# --- Load private key ---
priv_path = Path(f"{client_id}_private.pem")
if not priv_path.exists():
    raise SystemExit("Missing private key file")

with open(priv_path, "rb") as f_priv:
    client_private_key = serialization.load_pem_private_key(f_priv.read(), password=None)

def decrypt(enc_bytes):
    return client_private_key.decrypt(
        enc_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def sign(data: bytes) -> bytes:
    return client_private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

# --- Benchmarking ---
with open("results/api_rsa_puf_results.csv", "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["operation", "run", "duration_sec", "response_size_bytes", "memory_kb", "status"])

    for i in range(1, RUNS + 1):
        # Step 1: /auth/server
        tracemalloc.start()
        start = time.perf_counter()
        r = requests.post(f"{BASE}/auth/server", json={"client_id": client_id})
        duration = time.perf_counter() - start
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        writer.writerow(["server_verification", i, duration, len(r.content), peak // 1024, r.status_code])

        # Step 2: /auth/client
        tracemalloc.start()
        start = time.perf_counter()
        r = requests.post(f"{BASE}/auth/client", json={"client_id": client_id})
        duration = time.perf_counter() - start
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        writer.writerow(["client_verification", i, duration, len(r.content), peak // 1024, r.status_code])

        # Step 3: /auth/mutual (includes MAC)
        tracemalloc.start()
        start = time.perf_counter()
        r = requests.post(f"{BASE}/auth/mutual", json={"client_id": client_id, "mac": client_mac})
        duration = time.perf_counter() - start
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        res = r.json()
        writer.writerow(["mutual_auth", i, duration, len(r.content), peak // 1024, r.status_code])

        if "M4" not in res or "M5" not in res:
            print(f"❌ Run {i}: Missing M4/M5")
            continue

        # Step 4: Decrypt and sign
        try:
            m4_plain = decrypt(base64.b64decode(res["M4"]))
            m5_plain = decrypt(base64.b64decode(res["M5"]))
        except Exception as e:
            print(f"❌ Run {i}: Decryption failed - {e}")
            continue

        A, B = m4_plain[:-8], m5_plain[:-8]
        sig_b64 = base64.b64encode(sign(A + B)).decode()

        # Step 5: /auth/verify (includes MAC)
        tracemalloc.start()
        start = time.perf_counter()
        r = requests.post(f"{BASE}/auth/verify", json={
            "client_id": client_id,
            "M4": base64.b64encode(m4_plain).decode(),
            "M5": base64.b64encode(m5_plain).decode(),
            "signature": sig_b64,
            "mac": client_mac
        })
        duration = time.perf_counter() - start
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        writer.writerow(["verify_messages", i, duration, len(r.content), peak // 1024, r.status_code])
