# api/calculator.py
from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel
from typing import List, Optional
from auth.protocol import CLIENT_DB
import time

router = APIRouter()

class Numbers(BaseModel):
    client_id: str
    values: List[float]
    operation: str  
    session_id: str  


def check_authorized(client_id: str, session_id: str, auth_header: Optional[str]):
    """
    Ensure client is authenticated with both:
    - Bearer token (session_token)
    - Matching session_id
    """
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")

    token = auth_header.split(" ", 1)[1]
    client = CLIENT_DB.get(client_id)
    if not client:
        raise HTTPException(status_code=401, detail="Unknown client")

    if client.get("session_token") != token:
        raise HTTPException(status_code=401, detail="Invalid session token")

    if client.get("session_id") != session_id:
        raise HTTPException(status_code=401, detail="Invalid or mismatched session ID")

    expiry = client.get("session_expiry")
    if not expiry or int(time.time()) > int(expiry):
        client["authenticated"] = False
        client["session_token"] = None
        client["session_expiry"] = None
        client["session_id"] = None
        raise HTTPException(status_code=401, detail="Session expired; re-authenticate")


@router.post("/calculate")
def calculate(data: Numbers, Authorization: Optional[str] = Header(None)):
    check_authorized(data.client_id, data.session_id, Authorization)

    nums = data.values
    op = data.operation.lower()

    if not nums:
        raise HTTPException(status_code=400, detail="No numbers provided")

    if op == "sum":
        result = sum(nums)
    elif op == "avg":
        result = sum(nums) / len(nums)
    elif op == "max":
        result = max(nums)
    elif op == "min":
        result = min(nums)
    elif op == "multiply":
        result = 1
        for n in nums:
            result *= n
    else:
        raise HTTPException(status_code=400, detail=f"Unknown operation: {data.operation}")


    return {
        "operation": op,
        "numbers": nums,
        "result": result,
        "session_id": data.session_id,  
        "client_id": data.client_id
    }
