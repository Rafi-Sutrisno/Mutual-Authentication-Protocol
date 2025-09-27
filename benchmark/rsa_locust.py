from locust import HttpUser, task, between
import base64
from pathlib import Path
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

client_id = "client1"

priv_path = Path(f"{client_id}_private.pem")
with open(priv_path, "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

def decrypt(enc_bytes):
    return private_key.decrypt(
        enc_bytes,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def sign(data: bytes) -> bytes:
    return private_key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

class RSAUser(HttpUser):
    wait_time = between(0.1, 0.5)

    @task
    def authenticate(self):
        self.client.post("/auth/server", json={"client_id": client_id})

        self.client.post("/auth/client", json={"client_id": client_id})

        res = self.client.post("/auth/mutual", json={"client_id": client_id})
        try:
            data = res.json()
            m4 = decrypt(base64.b64decode(data["M4"]))
            m5 = decrypt(base64.b64decode(data["M5"]))
        except:
            return

        A, B = m4[:-8], m5[:-8]
        sig = base64.b64encode(sign(A + B)).decode()

        self.client.post("/auth/verify", json={
            "client_id": client_id,
            "M4": base64.b64encode(m4).decode(),
            "M5": base64.b64encode(m5).decode(),
            "signature": sig
        })
