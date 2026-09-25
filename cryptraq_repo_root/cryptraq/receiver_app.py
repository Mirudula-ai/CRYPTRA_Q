import streamlit as st
from PIL import Image
import numpy as np
import requests
import json
import base64
import time
import re
import fitz

from cryptraq.encryption.fernet_manager import EncryptionManager
from cryptraq.security.hashing import SecurityLayer
from cryptraq.database.db_manager import DatabaseManager
from cryptraq.encryption.steganography import SteganographyManager
import io

UUID_PATTERN = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
    re.IGNORECASE
)

st.set_page_config(page_title="CryptraQ Receiver Node", layout="wide", initial_sidebar_state="expanded")

# ---------- UI STYLING ----------
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;800&family=JetBrains+Mono:wght@400;700&display=swap');

:root {
    --primary: #3b82f6;
    --primary-dark: #2563eb;
    --bg-gradient: linear-gradient(135deg, #f0f9ff 0%, #e0f2fe 100%);
    --glass-bg: rgba(255, 255, 255, 0.7);
    --glass-border: rgba(59, 130, 246, 0.1);
    --text-main: #1e293b;
}

.stApp {
    background: var(--bg-gradient) !important;
    color: var(--text-main) !important;
    font-family: 'Inter', sans-serif !important;
}

.header-text {
    text-align: center;
    background: linear-gradient(90deg, #60a5fa, #a855f7);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    font-size: 3rem;
    font-weight: 800;
    margin-bottom: 2rem;
    letter-spacing: -1px;
}

.stButton>button {
    background: linear-gradient(180deg, #3b82f6 0%, #2563eb 100%);
    color: white !important;
    border: none;
    border-radius: 10px;
    padding: 0.75rem 1.5rem;
    font-weight: 600;
    transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    text-transform: none;
}

.stButton>button:hover {
    filter: brightness(1.1);
    box-shadow: 0 0 20px rgba(59, 130, 246, 0.4);
    transform: scale(1.02);
}

.alert {
    background: rgba(239, 68, 68, 0.2);
    color: #fca5a5;
    padding: 20px;
    border-radius: 12px;
    border: 1px solid rgba(239, 68, 68, 0.3);
    font-size: 1.2em;
    font-weight: bold;
    text-align: center;
    box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.3);
}

.validation-panel {
    background: var(--glass-bg);
    backdrop-filter: blur(12px);
    border: 1px solid var(--glass-border);
    border-radius: 16px;
    padding: 1.5rem;
    margin: 1.5rem 0;
}

.check-pass { color: #4ade80 !important; font-weight: 600; }
.check-fail { color: #f87171 !important; font-weight: 600; }
.check-warn { color: #fbbf24 !important; font-weight: 600; }

.stTextInput>div>div>input, .stTextArea>div>div>textarea {
    background: rgba(0, 0, 0, 0.2) !important;
    color: white !important;
    border: 1px solid var(--glass-border) !important;
    border-radius: 10px !important;
}

p, span, div, label, li, h1, h2, h3, h4, h5 {
    color: #334155 !important;
}

b, strong {
    color: #0f172a !important;
}

[data-testid="stSidebar"] {
    background: #f8fafc !important;
    border-right: 1px solid #e2e8f0;
}
</style>
""", unsafe_allow_html=True)

st.markdown('<div class="header-text">CryptraQ Tactical Receiver Node</div>', unsafe_allow_html=True)

# ---------- SESSION STATE ----------
_defaults = {
    "auth_step": "login",
    "failed_attempts": 0,
    "last_activity": time.time(),
    "username": None,
    # Auto-fill state
    "scan_t": "",   # relay token
    "scan_p": "",   # sender public key
    "scan_k": "",   # quantum session key
    "scan_h": "",   # HMAC integrity tag
    "scan_x": 0,    # expiration timestamp
    "scan_e": "",   # encrypted payload
    # Widget state
    "recv_token": "",
    "recv_pubkey": "",
    "recv_session_key": "",
    "recv_hmac": "",
    "recv_encrypted_payload": "",
    # Decrypt gate state
    "decrypt_verified": False,
    "decrypt_result": None,
}
for k, v in _defaults.items():
    if k not in st.session_state:
        st.session_state[k] = v

# Session Timeout check (15 mins)
if time.time() - st.session_state.last_activity > 900:
    for k in ["auth_step", "username", "failed_attempts", "decrypt_verified", "decrypt_result"]:
        st.session_state[k] = _defaults.get(k)
    st.warning("Session expired due to inactivity. Please login again.")

st.session_state.last_activity = time.time()

db = DatabaseManager()
import os
RELAY_URL = os.environ.get("RELAY_URL", "http://127.0.0.1:8000")

# ---------- RELAY HEALTH CHECK ----------
def check_relay_health():
    try:
        res = requests.get(f"{RELAY_URL}/health", timeout=1)
        if res.status_code == 200:
            return True
    except:
        pass
    return False

relay_online = check_relay_health()
if relay_online:
    st.sidebar.success("🟢 Relay Node: ONLINE")
else:
    st.sidebar.error("🔴 Relay Node: OFFLINE")
    st.sidebar.caption("Ensure the Relay Node is running at localhost:8000")

# ---------- AUTHENTICATION FLOW ----------
if st.session_state.failed_attempts >= 3:
    st.error("🔒 Too many failed attempts. Terminal locked.")
    st.stop()

if st.session_state.auth_step == 'login':
    st.subheader("Factor 1: Credential Verification")
    user = st.text_input("Username", value="mirudula", key="login_user")
    pwd  = st.text_input("Password", value="CryptraQ@SecureDefault!2026", type="password", key="login_pwd")
    if st.button("Authenticate"):
        if db.verify_user(user, pwd):
            st.session_state.username = user
            st.session_state.auth_step = 'authenticated'
            st.success("Credentials Verified.")
            st.rerun()
        else:
            st.session_state.failed_attempts += 1
            st.error("Invalid credentials.")
    st.stop()

# ---------- AUTHENTICATED DASHBOARD ----------
st.sidebar.title("Receiver Terminal")
st.sidebar.markdown(f"**Operator:** `{st.session_state.username}`")

if st.sidebar.button("Logout / Lock Terminal"):
    for k in list(st.session_state.keys()):
        del st.session_state[k]
    st.rerun()

# ---------- RETRIEVAL PROTOCOL ----------
st.subheader("Mission Retrieval Protocol")
st.info("🛡️ Zero-Trust Architecture Active. Packets are permanently destroyed upon retrieval.")

# ── Covert Image Steganography Extractor ────────────────────────────────────
st.markdown("#### 🖼️ Steganographic Covert Image Decoder")
st.caption(
    "Upload a covert mission image to extract hidden metadata. Auto-fills token and signatures."
)
scan_method = st.radio("Choose source", ["Upload Covert Image (JPEG/JPG/PNG/PDF)", "Use Camera"], horizontal=True)

extracted_data_raw = None
if scan_method == "Upload Covert Image (JPEG/JPG/PNG/PDF)":
    steg_file = st.file_uploader(
        "Upload Covert Mission Image (JPEG/JPG preferred, PNG/PDF also accepted)",
        type=["jpg", "jpeg", "png", "pdf"]
    )
    
    pdf_pwd = None
    if steg_file and steg_file.name.lower().endswith(".pdf"):
        pdf_pwd = st.text_input("PDF Password (required to extract image from PDF)", type="password")
        
    if steg_file and (not steg_file.name.lower().endswith(".pdf") or pdf_pwd):
        file_bytes = steg_file.read()
        try:
            if steg_file.name.lower().endswith(".pdf"):
                doc = fitz.open(stream=file_bytes, filetype="pdf")
                if doc.needs_pass:
                    if not doc.authenticate(pdf_pwd):
                        st.error("Incorrect PDF password.")
                        raise ValueError("Incorrect password")
                
                img_pil = None
                for page_index in range(len(doc)):
                    page = doc[page_index]
                    image_list = page.get_images(full=True)
                    for img_info in image_list:
                        xref = img_info[0]
                        base_image = doc.extract_image(xref)
                        image_bytes = base_image["image"]
                        try:
                            tmp_pil = Image.open(io.BytesIO(image_bytes)).convert('RGB')
                            tmp_array = np.array(tmp_pil)
                            if SteganographyManager.extract_data(tmp_array):
                                img_pil = tmp_pil
                                break
                        except Exception:
                            pass
                    if img_pil:
                        break
                if not img_pil:
                    raise ValueError("No valid steganographic image found in PDF.")
            else:
                # JPEG, PNG, or any PIL-readable image
                img_pil = Image.open(io.BytesIO(file_bytes)).convert('RGB')
                
            img_array = np.array(img_pil)
            extracted_bytes = SteganographyManager.extract_data(img_array)
            if extracted_bytes:
                extracted_data_raw = extracted_bytes.decode('utf-8')
            else:
                st.warning("No BMCS payload found. This may be an older PNG image — try re-downloading from the sender.")
        except Exception as e:
            st.error(f"Failed to process image: {e}")
else:
    steg_camera = st.camera_input("Take photo of Covert Image")
    if steg_camera:
        file_bytes = steg_camera.read()
        try:
            img_pil = Image.open(io.BytesIO(file_bytes)).convert('RGB')
            img_array = np.array(img_pil)
            extracted_bytes = SteganographyManager.extract_data(img_array)
            if extracted_bytes:
                extracted_data_raw = extracted_bytes.decode('utf-8')
        except Exception as e:
            pass

# ── Auto-fill logic — fills fields, does NOT decrypt ──────────────────────
if extracted_data_raw:
    try:
        # Normalize data
        extracted_data_raw = extracted_data_raw.strip()
        steg_dict = json.loads(extracted_data_raw)
        
        # 1. Update intermediate scan state
        new_t = steg_dict.get("t", "")
        new_p = steg_dict.get("p", "")
        new_h = steg_dict.get("h", "")
        new_k = steg_dict.get("k", "")
        new_x = int(steg_dict.get("x", 0))
        new_e = steg_dict.get("e", "")

        # Check if values have actually changed before rerunning to avoid loops
        # Use .get() to avoid KeyError if widgets haven't been rendered yet
        has_changed = (
            st.session_state.get("scan_t", "") != new_t or
            st.session_state.get("scan_p", "") != new_p or
            st.session_state.get("scan_h", "") != new_h or
            st.session_state.get("scan_k", "") != new_k or
            st.session_state.get("scan_e", "") != new_e
        )

        if has_changed:
            st.session_state.scan_t = new_t
            st.session_state.scan_p = new_p
            st.session_state.scan_h = new_h
            st.session_state.scan_k = new_k
            st.session_state.scan_x = new_x
            st.session_state.scan_e = new_e

            # 2. Directly update the text_input widget keys to force UI auto-fill
            st.session_state.recv_token = new_t
            st.session_state.recv_pubkey = new_p
            st.session_state.recv_hmac = new_h
            st.session_state.recv_session_key = new_k
            st.session_state.recv_encrypted_payload = new_e

            # Reset any prior decrypt result when new data is extracted
            st.session_state.decrypt_verified = False
            st.session_state.decrypt_result = None
            st.success("✅ Covert payload decoded. ALL mission fields auto-filled.")
            st.rerun()  # Force a rerun to show the updated values immediately
        else:
            st.success("✅ Covert data already loaded.")

    except json.JSONDecodeError:
        # Legacy plain-token fallback
        if st.session_state.get("recv_token", "") != extracted_data_raw:
            st.session_state.scan_t = extracted_data_raw
            st.session_state.recv_token = extracted_data_raw
            st.session_state.scan_h = ""
            st.session_state.scan_p = ""
            st.session_state.scan_x = 0
            st.session_state.scan_e = ""
            st.warning("Data contains legacy plain token format. Enter Public Key and Session Key manually.")
            st.rerun()
    except Exception as e:
        st.error(f"Failed to process hidden data: {e}")

elif scan_method == "Upload Covert Image (JPEG/JPG/PNG/PDF)" and 'steg_file' in locals() and steg_file:
    if steg_file.name.lower().endswith(".pdf") and not pdf_pwd:
        st.info("Please enter the PDF password to continue.")
    else:
        st.error("No steganographic payload detected in uploaded file. Ensure you uploaded the correct covert image.")
elif scan_method == "Use Camera" and 'steg_camera' in locals() and steg_camera:
    # We only show this if a photo was taken but no payload found
    st.error("No steganographic payload detected via camera. Try adjusting distance or lighting.")

st.markdown("---")

# ── Manual field entry (auto-filled from QR scan above) ──────────────────────
st.markdown("#### 🗝️ Retrieval Credentials")

token = st.text_input(
    "One-Time Retrieval Token",
    placeholder="e.g. 550e8400-e29b-41d4-a716-446655440000",
    key="recv_token"
)
session_key = st.text_input(
    "Quantum Session Key (32-bit)",
    type="password",
    placeholder="Auto-filled from image or enter manually...",
    key="recv_session_key"
)
public_key = st.text_input(
    "Sender Public Key (for Ed25519 Signature Verification)",
    key="recv_pubkey"
)
hmac_tag_input = st.text_input(
    "Ed25519 Binding Signature (auto-filled from image — proves image was signed by sender)",
    key="recv_hmac"
)
encrypted_payload_input = st.text_area(
    "Encrypted Payload (auto-filled from image)",
    disabled=True,
    key="recv_encrypted_payload"
)

# (Security checks are performed silently to enable the button)
check_token = bool(token) and bool(UUID_PATTERN.match(token.strip()))
check_key = bool(session_key) and len(session_key.strip()) >= 16
check_pubkey = bool(public_key) and len(public_key.strip()) == 64
check_auth = st.session_state.auth_step == 'authenticated'
check_hmac = bool(hmac_tag_input) and len(hmac_tag_input.strip()) >= 80
expiry_val = st.session_state.scan_x
remaining = expiry_val - time.time() if expiry_val > 0 else 1
check_expiry = remaining > 0 if expiry_val > 0 else True

# All mandatory checks
all_mandatory_pass = check_token and check_key and check_pubkey and check_auth

# ── Ed25519 Binding Pre-Verification (before hitting relay) ──────────────────
if all_mandatory_pass and check_hmac and expiry_val > 0:
    binding_valid = SecurityLayer.verify_binding(
        token=token.strip(),
        expiration=expiry_val,
        binding_sig=hmac_tag_input.strip(),
        public_key_hex=public_key.strip(),
    )
    if binding_valid:
        st.success(
            "🔐 Ed25519 binding signature verified -- Image/PDF was signed by the "
            "holder of the sender private key. Token and expiry are authentic."
        )
    else:
        st.error(
            "❌ BINDING SIGNATURE VERIFICATION FAILED -- Token, expiry, or public key "
            "has been tampered with, or this image was not produced by the claimed sender. "
            "Do NOT proceed. Abort retrieval."
        )
        all_mandatory_pass = False  # Hard block: forged or replayed image

# ── Password Re-Confirmation Gate before Retrieval ───────────────────────────
st.markdown("---")
st.markdown("#### 🔒 Identity Re-Confirmation Before Retrieval")
st.caption("Enter your password to confirm your identity. This prevents unauthorised relay queries.")

reauth_pwd = st.text_input(
    "Confirm Password",
    value="CryptraQ@SecureDefault!2026",
    type="password",
    key="recv_reauth_pwd",
    placeholder="Re-enter your login password..."
)
check_reauth = bool(reauth_pwd)

if not all_mandatory_pass:
    st.warning("⛔ Resolve all failed security checks above before proceeding.")

# ── Explicit Verified Decrypt Button ─────────────────────────────────────────
decrypt_button_label = "🔐 Verified Decrypt — Retrieve & Authenticate Packet"

if st.button(decrypt_button_label, disabled=not all_mandatory_pass):
    # Final re-auth check at click time
    if not reauth_pwd:
        st.error("Password re-confirmation is required before retrieval.")
    elif not db.verify_user(st.session_state.username, reauth_pwd):
        st.session_state.failed_attempts += 1
        st.error(f"❌ Password verification failed. Attempt {st.session_state.failed_attempts}/3.")
    else:
        st.session_state.decrypt_verified = True
        st.session_state.decrypt_result = None

        with st.spinner("Interrogating Relay Node under zero-trust protocol..."):
            try:
                # ── Retrieve from Relay (one-time — packet self-destructs) ──
                response = requests.get(f"{RELAY_URL}/retrieve/{token.strip()}")

                if response.status_code == 200:
                    packet = response.json()['packet']
                    st.success("✅ Packet retrieved. Self-destructed from vault — one-time use consumed.")

                    encrypted_payload = packet['payload']
                    signature         = packet['signature']

                    # ── Verify Ed25519 Signature ──────────────────────────
                    st.write("🔍 Verifying Ed25519 digital signature...")
                    
                    # Fallback to packet payload if not auto-filled
                    payload_to_decrypt = encrypted_payload_input if encrypted_payload_input else encrypted_payload
                    
                    is_authentic = SecurityLayer.verify_signature(
                        payload_to_decrypt, signature, public_key.strip()
                    )

                    if not is_authentic:
                        st.error(
                            "⚠️ SIGNATURE VERIFICATION FAILED! "
                            "Encrypted payload has been tampered with or key is invalid. "
                            "Aborting decryption."
                        )
                        st.session_state.decrypt_verified = False
                    else:
                        st.success("✅ Signature authentic — payload integrity confirmed.")

                        # ── Decrypt Payload ───────────────────────────────
                        try:
                            decrypted_json = EncryptionManager.decrypt_message(
                                payload_to_decrypt, session_key.strip()
                            )
                            
                            try:
                                payload = json.loads(decrypted_json)
                                decrypted_msg = payload.get("text", "")
                                audio_base64 = payload.get("audio", None)
                            except json.JSONDecodeError:
                                # Fallback for legacy plain-text packets
                                decrypted_msg = decrypted_json
                                audio_base64 = None

                            # ── Emergency keyword detection ───────────────
                            emergency_keywords = ["STOP", "EVACUATE", "RETREAT", "ALERT"]
                            is_emergency = any(word in decrypted_msg.upper() for word in emergency_keywords)

                            st.session_state.decrypt_result = {
                                "message": decrypted_msg,
                                "audio": audio_base64,
                                "is_emergency": is_emergency,
                            }
                        except Exception as e:
                            st.error(
                                f"❌ Decryption failed — session key is likely incorrect.\n"
                                f"Error: {str(e)}"
                            )

                elif response.status_code == 410:
                    st.warning("⚠️ Packet expired and self-destructed before retrieval.")
                elif response.status_code == 404:
                    st.error("❌ Invalid token — packet not found or already retrieved (one-time use).")
                else:
                    detail = response.json().get('detail', 'Unknown Error')
                    st.error(f"Relay Node Error: {detail}")

            except requests.exceptions.ConnectionError:
                st.error("🔌 Connection refused. Secure Relay Node is offline.")
            except Exception as e:
                st.error(f"Retrieval failed: {str(e)}")

# ── Decrypted Message Display ─────────────────────────────────────────────────
if st.session_state.decrypt_result:
    result = st.session_state.decrypt_result
    st.markdown("---")
    st.markdown("### 📨 Decrypted Tactical Transmission")

    if result["is_emergency"]:
        st.markdown(
            f'<div class="alert">⚠️ {result["message"]} ⚠️</div>',
            unsafe_allow_html=True
        )
    else:
        if result["message"]:
            st.info(result["message"])

    if result["audio"]:
        st.markdown("#### 🔊 Voice Message Attached")
        try:
            audio_bytes = base64.b64decode(result["audio"])
            st.audio(audio_bytes)
        except Exception as e:
            st.error(f"Failed to decode audio: {e}")

    st.caption("Message displayed in-session only. Not stored anywhere. Refresh to clear.")

    if st.button("🗑️ Clear Decrypted Message"):
        st.session_state.decrypt_result = None
        st.rerun()
