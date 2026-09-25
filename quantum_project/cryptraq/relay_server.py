from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uuid
import time
import uvicorn
import logging
import json

from cryptraq.database.db_manager import DatabaseManager
from cryptraq.packets.models import MissionPacket, DepositResponse, RetrieveResponse

# ---------- Structured Security Audit Logger ----------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
logger = logging.getLogger("RelayServer")
audit = logging.getLogger("SecurityAudit")

def _audit(event: str, detail: dict):
    """Emit a structured JSON security audit log entry."""
    entry = {
        "event": event,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        **detail,
    }
    audit.info(json.dumps(entry))

# ---------- App ----------
app = FastAPI(title="CryptraQ Secure Relay Node", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8501", "http://127.0.0.1:8501"],  # Restricted to local Streamlit
    allow_credentials=True,
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)

# Dependency to get DB + auto-purge expired packets
def get_db():
    db = DatabaseManager()
    purged = db.delete_expired_packets(time.time())
    if purged and purged > 0:
        _audit("PURGE_EXPIRED", {"count": purged})
    yield db


@app.post("/deposit", response_model=DepositResponse)
async def deposit_packet(packet: MissionPacket, request: Request, db: DatabaseManager = Depends(get_db)):
    """
    Deposits a secure mission packet into the Relay Vault.
    Generates a one-time retrieval token.
    The relay stores only the encrypted payload — never plaintext.
    """
    client_ip = request.client.host if request.client else "unknown"

    if packet.is_expired():
        _audit("DEPOSIT_REJECTED_EXPIRED", {
            "session_id": packet.session_id,
            "expiration": packet.expiration,
            "client_ip": client_ip,
        })
        raise HTTPException(status_code=400, detail="Packet has already expired before deposit.")

    # Verify the packet payload is non-empty and looks like Fernet ciphertext
    if not packet.payload or len(packet.payload) < 20:
        _audit("DEPOSIT_REJECTED_INVALID_PAYLOAD", {
            "session_id": packet.session_id,
            "client_ip": client_ip,
        })
        raise HTTPException(status_code=400, detail="Invalid or empty payload.")

    # Generate one-time secure retrieval token
    token = str(uuid.uuid4())

    success = db.store_packet(token, packet.dict())
    if not success:
        _audit("DEPOSIT_STORE_FAILED", {
            "session_id": packet.session_id,
            "client_ip": client_ip,
        })
        raise HTTPException(status_code=500, detail="Failed to store packet in vault.")

    ttl_seconds = max(0, packet.expiration - int(time.time()))
    _audit("DEPOSIT_SUCCESS", {
        "token_prefix": token[:8],
        "session_id": packet.session_id,
        "expiration": packet.expiration,
        "ttl_seconds": ttl_seconds,
        "has_hmac": packet.hmac_tag is not None,
        "client_ip": client_ip,
    })
    logger.info(f"Packet deposited. Session: {packet.session_id}. TTL: {ttl_seconds}s.")

    return DepositResponse(
        status="success",
        token=token,
        message="Packet stored successfully in vault. One-time retrieval token issued."
    )


@app.get("/retrieve/{token}", response_model=RetrieveResponse)
async def retrieve_packet(token: str, request: Request, db: DatabaseManager = Depends(get_db)):
    """
    Retrieves a mission packet using a one-time token.
    Immediately and permanently deletes the packet from the vault (zero-trust).
    Any second attempt with the same token returns 404.
    """
    client_ip = request.client.host if request.client else "unknown"

    # Basic UUID format check — reject probing attempts with junk tokens
    import re
    UUID_PATTERN = re.compile(
        r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
        re.IGNORECASE
    )
    if not UUID_PATTERN.match(token):
        _audit("RETRIEVE_INVALID_TOKEN_FORMAT", {
            "token_prefix": token[:16] if len(token) >= 16 else token,
            "client_ip": client_ip,
        })
        raise HTTPException(status_code=400, detail="Invalid token format.")

    # Retrieve and immediately delete (one-time use)
    packet_data = db.retrieve_and_delete_packet(token)

    if not packet_data:
        _audit("RETRIEVE_NOT_FOUND", {
            "token_prefix": token[:8],
            "client_ip": client_ip,
            "note": "Token invalid, already consumed, or expired.",
        })
        raise HTTPException(
            status_code=404,
            detail="Invalid token or packet already accessed/expired. One-time use consumed."
        )

    packet = MissionPacket(**packet_data)

    if packet.is_expired():
        _audit("RETRIEVE_EXPIRED_POST_FETCH", {
            "token_prefix": token[:8],
            "session_id": packet.session_id,
            "expired_at": packet.expiration,
            "client_ip": client_ip,
            "note": "Packet expired between storage and retrieval. Data discarded.",
        })
        raise HTTPException(status_code=410, detail="Packet has expired and self-destructed.")

    _audit("RETRIEVE_SUCCESS", {
        "token_prefix": token[:8],
        "session_id": packet.session_id,
        "payload_len": len(packet.payload),
        "has_signature": bool(packet.signature),
        "has_hmac": packet.hmac_tag is not None,
        "client_ip": client_ip,
    })
    logger.info(f"Packet retrieved and deleted. Session: {packet.session_id}.")

    return RetrieveResponse(
        status="success",
        packet=packet,
        message="Packet retrieved. Self-destructed from vault. One-time use consumed."
    )


@app.get("/health")
async def health_check():
    """Simple health endpoint for relay status monitoring."""
    return {"status": "online", "node": "CryptraQ Relay Vault v2", "timestamp": time.time()}


if __name__ == "__main__":
    logger.info("Starting CryptraQ Relay Node Zero-Trust Vault v2...")
    uvicorn.run("cryptraq.relay_server:app", host="0.0.0.0", port=8000, reload=True)
