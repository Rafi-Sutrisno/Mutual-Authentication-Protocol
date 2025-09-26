from fastapi import APIRouter
from pydantic import BaseModel
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature
from .crypto_utils import *
import base64, time, json, uuid, secrets, hashlib
from pathlib import Path
from typing import Optional

router = APIRouter()
DB_FILE = Path("clients.json")

# ---------------- Server key management ----------------
SERVER_KEYS = []
def create_new_server_key():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = priv.public_key()
    kid = str(uuid.uuid4())
    entry = {"kid": kid, "private": priv, "public": pub, "created": int(time.time())}
    SERVER_KEYS.insert(0, entry)
    if len(SERVER_KEYS) > 4:
        SERVER_KEYS.pop()
    return entry

_current_key_entry = create_new_server_key()
def current_server_private_key(): return SERVER_KEYS[0]["private"]
def current_server_public_key(): return SERVER_KEYS[0]["public"]

# ---------------- Persistence / DB ----------------
if DB_FILE.exists():
    with open(DB_FILE, "r") as f:
        raw = json.load(f)
    CLIENT_DB = {}
    for cid, data in raw.items():
        shared_key = bytes.fromhex(data["shared_key"])
        cid_bytes = data["cid"].encode()
        pub_pem = data.get("public_key_pem")
        pub_obj = None
        if pub_pem:
            try:
                pub_obj = serialization.load_pem_public_key(pub_pem.encode())
            except Exception:
                pub_obj = None
        CLIENT_DB[cid] = {
            "cid": cid_bytes,
            "shared_key": shared_key,
            "public_key": pub_obj,
            "public_key_pem": pub_pem,
            "mac": data.get("mac"),   
            "Gn": None,
            "authenticated": False,
            "session_token": None,
            "session_expiry": None,
            "session_id": None,
            "used_session_ids": []
        }
else:
    CLIENT_DB = {}

def save_clients():
    serializable = {}
    for cid, data in CLIENT_DB.items():
        serializable[cid] = {
            "cid": data["cid"].decode(),
            "shared_key": data["shared_key"].hex(),
            "public_key_pem": data.get("public_key_pem") or None,
            "mac": data.get("mac") 
        }
    with open(DB_FILE, "w") as f:
        json.dump(serializable, f, indent=2)

SERVER_ID = "server123"

# ---------------- Nonce caching ----------------
USED_GNS = {}
GN_GRACE_SECONDS = 300
def add_used_gn(gn: bytes): USED_GNS[gn.hex()] = int(time.time()) + GN_GRACE_SECONDS; cleanup_used_gns()
def is_gn_used(gn: bytes) -> bool: cleanup_used_gns(); return gn.hex() in USED_GNS
def cleanup_used_gns(): now = int(time.time()); [USED_GNS.pop(k) for k,v in list(USED_GNS.items()) if v<now]

# ---------------- Schemas ----------------
class ClientRequest(BaseModel):
    client_id: str
    mac: Optional[str] = None  

class PublicKeyRegister(BaseModel):
    client_id: str
    public_key_pem: str
    mac: Optional[str] = None   

class VerifyPayload(BaseModel):
    client_id: str
    M4: str
    M5: str
    signature: str
    mac: Optional[str] = None

class NewClientRequest(BaseModel):
    client_id: str
    shared_key: Optional[str] = None

# ---------------- Endpoints ----------------

@router.post("/new_client")
def create_new_client(req: NewClientRequest):
    if req.client_id in CLIENT_DB:
        return {"error": "Client ID already exists"}
    if req.shared_key:
        try:
            shared_key = bytes.fromhex(req.shared_key)
        except Exception:
            shared_key = req.shared_key.encode()
    else:
        shared_key = secrets.token_bytes(16)

    CLIENT_DB[req.client_id] = {
        "cid": req.client_id.encode(),
        "shared_key": shared_key,
        "public_key": None,
        "public_key_pem": None,
        "mac": None, 
        "Gn": None,
        "authenticated": False,
        "session_token": None,
        "session_expiry": None,
        "session_id": None,
        "used_session_ids": []
    }
    save_clients()
    return {"status": "Client registered successfully", "client_id": req.client_id, "shared_key": shared_key.hex()}

@router.post("/register")
def register_client_key(req: PublicKeyRegister):
    client = CLIENT_DB.get(req.client_id)
    if not client: return {"error": "Unknown client"}
    if client.get("public_key_pem") and client["public_key_pem"].strip() != req.public_key_pem.strip():
        return {"error": "Public key already registered and cannot be changed"}
    try:
        pub_key = serialization.load_pem_public_key(req.public_key_pem.encode())
        client["public_key"] = pub_key
        client["public_key_pem"] = req.public_key_pem
        if req.mac: client["mac"] = req.mac.lower()  
        save_clients()
        return {"status": "Public key registered successfully", "mac": client["mac"]}
    except Exception as e:
        return {"error": f"Invalid public key format: {e}"}

@router.post("/server")
def server_verification(req: ClientRequest):
    client = CLIENT_DB.get(req.client_id)
    if not client:
        return {"error": "Unknown client"}
    h_sid = hash_sid(SERVER_ID)
    t1 = int(time.time()).to_bytes(8, 'big')
    payload = h_sid + t1
    iv, encrypted = aes_encrypt(client["shared_key"], payload)
    return {"iv": base64.b64encode(iv).decode(), "data": base64.b64encode(encrypted).decode()}

@router.post("/client")
def client_verification(req: ClientRequest):
    client = CLIENT_DB.get(req.client_id)
    if not client or not client.get("public_key"):
        return {"error": "Unknown client or public key not set"}
    cid = client["cid"]
    h_sid = hash_sid(SERVER_ID)
    xor_result = xor_bytes(cid, h_sid)
    t2 = int(time.time()).to_bytes(8, 'big')
    payload = xor_result + t2

    enc = current_server_public_key().encrypt(payload, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    ))
    return {"data": base64.b64encode(enc).decode(), "server_kid": SERVER_KEYS[0]["kid"]}


@router.post("/mutual")
def mutual_auth(req: ClientRequest):
    client = CLIENT_DB.get(req.client_id)
    if not client or not client.get("public_key"):
        return {"error": "Unknown client or missing public key"}
    if not client.get("mac"):
        return {"error": "MAC not registered for this client"}

    if req.mac and req.mac.lower() != client["mac"].lower():
        return {"error": f"MAC address mismatch {req.mac.lower()} and {client["mac"].lower()}"}

    cid, mac = client["cid"], client["mac"]

    Gn = generate_nonce(16)
    while is_gn_used(Gn): Gn = generate_nonce(16)
    client["Gn"] = Gn
    add_used_gn(Gn)

    Kn, Kn1 = F(Gn), F(F(Gn))
    Gn1 = simulate_puf(Gn, mac)
    Gn2 = simulate_puf(Gn1, mac)

    A = xor_bytes(xor_bytes(Gn1, Kn), cid)
    B = xor_bytes(xor_bytes(Gn2, Kn1), cid)
    t4 = int(time.time()).to_bytes(8, 'big')

    enc1 = client["public_key"].encrypt(A+t4, padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    enc2 = client["public_key"].encrypt(B+t4, padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

    return {"M4": base64.b64encode(enc1).decode(), "M5": base64.b64encode(enc2).decode()}

@router.post("/verify")
def verify_messages(req: VerifyPayload):
    client = CLIENT_DB.get(req.client_id)
    if not client or not client.get("Gn") or not client.get("public_key"):
        return {"error": "Client not found or Gn not set"}

    if req.mac and req.mac.lower() != client["mac"].lower():
        return {"error": "MAC address mismatch"}

    cid, Gn, mac = client["cid"], client["Gn"], client["mac"]
    
    Kn, Kn1 = F(Gn), F(F(Gn))
    Gn1 = simulate_puf(Gn, mac) 
    Gn2 = simulate_puf(Gn1, mac)
    A_expected, B_expected = xor_bytes(xor_bytes(Gn1, Kn), cid), xor_bytes(xor_bytes(Gn2, Kn1), cid)

    try:
        m4_bytes, m5_bytes, sig_bytes = base64.b64decode(req.M4), base64.b64decode(req.M5), base64.b64decode(req.signature)
        if len(m4_bytes)<8 or len(m5_bytes)<8: return {"error": "Malformed M4/M5"}
        A_received, B_received = m4_bytes[:-8], m5_bytes[:-8]
        if not (A_received == A_expected and B_received == B_expected): return {"status": "Authentication FAILED - mismatch"}

        client["public_key"].verify(sig_bytes, A_received+B_received, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

        client["Gn"], client["authenticated"] = Gn1, True
        SK = hashlib.sha256(Gn+Kn+cid).digest()
        token, expiry = base64.urlsafe_b64encode(SK).decode(), int(time.time())+300
        session_id = str(uuid.uuid4())
        client.update({"session_token": token,"session_expiry": expiry,"session_id": session_id})
        client["used_session_ids"].append(session_id)

        return {"status": "Mutual authentication SUCCESS","session_token": token,"session_id": session_id,"expires_at": expiry}
    except InvalidSignature:
        return {"error": "Invalid client signature"}
    except Exception as e:
        return {"error": f"Verification failed: {e}"}
