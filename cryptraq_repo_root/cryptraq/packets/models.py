from pydantic import BaseModel, Field
from typing import Optional
import time
import uuid

class MissionPacket(BaseModel):
    payload: str = Field(..., description="Encrypted payload base64 string")
    session_id: str = Field(..., description="Unique session ID for this transmission")
    expiration: int = Field(..., description="Unix timestamp when packet expires and should self-destruct")
    signature: str = Field(..., description="Ed25519 digital signature of the encrypted payload")
    timestamp: float = Field(default_factory=time.time, description="Creation timestamp")
    hmac_tag: Optional[str] = Field(None, description="HMAC integrity tag binding token+public_key+expiry (no session key)")

    def is_expired(self) -> bool:
        return time.time() > self.expiration

    def remaining_seconds(self) -> float:
        return max(0.0, self.expiration - time.time())

class DepositResponse(BaseModel):
    status: str
    token: str
    message: str

class RetrieveResponse(BaseModel):
    status: str
    packet: Optional[MissionPacket]
    message: str
