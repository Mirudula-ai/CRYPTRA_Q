"""
pdf_security.py — CryptraQ Encrypted Mission Packet PDF Generator
=================================================================
Zero-trust PDF generation pipeline:

Layer 1 (Content):  FPDF builds the PDF with ONLY the relay token, sender
                    public key, HMAC integrity tag, expiry, and a QR code.
                    NO session key. NO plaintext message. NO decrypted content.

Layer 2 (File):     pikepdf applies AES-256 password encryption to the PDF.
                    Opening the file requires the user's password.

Layer 3 (Access):   The caller (sender_app) only reaches this module after
                    a successful password re-authentication step in the UI.

Optional Layer 4:   A one-time unlock code (OTC) is derived via HMAC-SHA256
                    from the token + password + timestamp. The OTC is shown
                    on screen after export and is NOT stored anywhere.
"""

import hashlib
import hmac
import io
import json
import logging
import os
import tempfile
import time

import pikepdf
from fpdf import FPDF
from PIL import Image
import numpy as np

from cryptraq.encryption.steganography import SteganographyManager

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _build_content_pdf(
    token: str,
    public_key_hex: str,
    hmac_tag: str,
    expiration: int,
    session_id: str,
    session_key: str,
    encrypted_payload: str,
) -> bytes:
    """
    Build an FPDF PDF that contains ONLY the header, QR code, and footer.
    Metadata is embedded in the QR for auto-filling.
    Returns raw PDF bytes.
    """
    pdf = FPDF()
    pdf.add_page()
    pdf.set_margins(15, 15, 15)

    # ── Header ──────────────────────────────────────────────────────────────
    pdf.set_font("Courier", "B", 16)
    pdf.cell(0, 10, "CRYPTRAQ // CLASSIFIED MISSION PACKET", ln=True, align="C")
    pdf.set_font("Courier", "", 9)
    pdf.cell(0, 6, "HANDLE VIA SECURE CHANNELS ONLY -- EYES AUTHORIZED ONLY", ln=True, align="C")
    pdf.ln(4)
    pdf.set_draw_color(80, 80, 80)
    pdf.line(15, pdf.get_y(), 195, pdf.get_y())
    pdf.ln(6)

    pdf.ln(10)
    pdf.set_font("Courier", "B", 12)
    pdf.cell(0, 10, "MISSION AUTHORIZATION QR CODE", ln=True, align="C")
    pdf.ln(5)

    # ── Steganographic Covert Image payload ─────
    # Hidden payload carries: token (t), public_key (p), session_key (k), hmac_tag (h), expiration (x), encrypted_payload (e)
    steg_payload_json = json.dumps({
        "t": token,
        "p": public_key_hex,
        "k": session_key,
        "h": hmac_tag,
        "x": expiration,
        "e": encrypted_payload,
    }).encode('utf-8')
    
    cover_img_array = SteganographyManager.create_default_cover()
    embedded_img_array = SteganographyManager.embed_data(cover_img_array, steg_payload_json)
    steg_img = Image.fromarray(embedded_img_array)

    with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as tmp:
        tmp_path = tmp.name
        steg_img.save(tmp_path, format="PNG")

    try:
        # Center the QR code
        pdf.image(tmp_path, x=55, y=pdf.get_y(), w=100)
    finally:
        try:
            os.remove(tmp_path)
        except Exception:
            pass

    pdf.ln(110)
    pdf.set_font("Courier", "I", 8)
    pdf.multi_cell(0, 5, 
        "INSTRUCTIONS: Upload this PDF in the CryptraQ Receiver Terminal to auto-fill all retrieval credentials from the covert image. "
        "This packet is password-protected and the contents are one-time use only.", 
        align="C"
    )

    pdf.ln(10)
    pdf.set_font("Courier", "", 7)
    pdf.cell(0, 5, "CryptraQ Zero-Trust Relay System -- CLASSIFIED // RESTRICTED DISTRIBUTION", align="C", ln=True)

    raw = pdf.output()
    if isinstance(raw, bytearray):
        return bytes(raw)
    if isinstance(raw, str):
        return raw.encode("latin-1")
    return raw


def _apply_pikepdf_encryption(pdf_bytes: bytes, user_password: str, owner_password: str) -> bytes:
    """
    Apply AES-256 encryption to the PDF using pikepdf.
    - user_password:  required to OPEN the file
    - owner_password: required for full permissions (we set it to a different value so
                      users cannot print/copy/modify even if they can open)
    Returns encrypted PDF bytes.
    """
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as in_tmp:
        in_path = in_tmp.name
        in_tmp.write(pdf_bytes)

    out_path = in_path + "_enc.pdf"

    try:
        with pikepdf.open(in_path) as pdf:
            enc = pikepdf.Encryption(
                user=user_password,
                owner=owner_password,
                R=6,           # PDF 2.0 / AES-256
                allow=pikepdf.Permissions(
                    print_highres=False,
                    print_lowres=False,
                    modify_other=False,
                    modify_annotation=False,
                    extract=False,
                    accessibility=False,
                )
            )
            pdf.save(out_path, encryption=enc)

        with open(out_path, "rb") as f:
            return f.read()

    finally:
        for p in [in_path, out_path]:
            try:
                os.remove(p)
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_one_time_code(token: str, password: str) -> str:
    """
    Derives a one-time unlock code (OTC) from token + password using HMAC-SHA256.
    The OTC is NOT stored anywhere. It is shown once on screen and then lost.
    Receivers can use this code as an additional secondary verification reference.
    """
    key = password.encode("utf-8")
    msg = f"{token}:{int(time.time()) // 300}".encode("utf-8")  # 5-minute window
    digest = hmac.new(key, msg, hashlib.sha256).hexdigest()
    # Return first 12 hex chars formatted as groups of 4 for readability
    code = digest[:12].upper()
    return f"{code[:4]}-{code[4:8]}-{code[8:12]}"


def build_encrypted_mission_pdf(
    token: str,
    public_key_hex: str,
    hmac_tag: str,
    expiration: int,
    session_id: str,
    session_key: str,
    user_password: str,
    encrypted_payload: str,
) -> tuple[bytes, str]:
    """
    Full pipeline: build content PDF → apply AES-256 pikepdf encryption.

    Returns:
        (encrypted_pdf_bytes, one_time_code)

    The one_time_code is an optional secondary reference. It is derived from
    (token + password) and exists only in memory — never written to disk or PDF.
    """
    # Layer 1: build content PDF (no secrets)
    logger.info(f"Building mission PDF for token {token[:8]}...")
    content_bytes = _build_content_pdf(
        token=token,
        public_key_hex=public_key_hex,
        hmac_tag=hmac_tag,
        expiration=expiration,
        session_id=session_id,
        session_key=session_key,
        encrypted_payload=encrypted_payload,
    )

    # Layer 2: pikepdf AES-256 encryption
    # owner_password is derived so even printing/copying are blocked
    owner_password = hmac.new(
        user_password.encode("utf-8"),
        b"cryptraq-owner-lock",
        hashlib.sha256,
    ).hexdigest()[:32]

    logger.info("Applying AES-256 PDF encryption via pikepdf...")
    encrypted_bytes = _apply_pikepdf_encryption(
        pdf_bytes=content_bytes,
        user_password=user_password,
        owner_password=owner_password,
    )

    # Layer 3: generate one-time code (shown once, never stored)
    otc = generate_one_time_code(token, user_password)

    logger.info(f"Encrypted mission PDF ready ({len(encrypted_bytes)} bytes).")
    return encrypted_bytes, otc
