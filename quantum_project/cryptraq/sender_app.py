import streamlit as st
from io import BytesIO
import requests
import json
import time
import uuid
from PIL import Image
from streamlit_mic_recorder import speech_to_text, mic_recorder

from cryptraq.quantum.key_gen import QuantumSimulator
from cryptraq.encryption.fernet_manager import EncryptionManager
from cryptraq.security.hashing import SecurityLayer
from cryptraq.database.db_manager import DatabaseManager
from cryptraq.pdf_security import build_encrypted_mission_pdf, generate_one_time_code
from cryptraq.encryption.steganography import SteganographyManager
import numpy as np

st.set_page_config(page_title="CryptraQ Sender Node", layout="wide", initial_sidebar_state="expanded")

# ---------- UI STYLING & THEME ----------
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;800&family=JetBrains+Mono:wght@400;700&display=swap');

:root {
    --primary: #3b82f6;
    --primary-dark: #1d4ed8;
    --bg-gradient: linear-gradient(135deg, #f0f9ff 0%, #e0f2fe 100%);
    --glass-bg: rgba(255, 255, 255, 0.7);
    --glass-border: rgba(59, 130, 246, 0.1);
    --text-main: #1e293b;
    --header-gradient: linear-gradient(90deg, #1d4ed8, #7c3aed);
}

.stApp {
    background: var(--bg-gradient) !important;
    color: var(--text-main) !important;
    font-family: 'Inter', sans-serif !important;
}

.header-text {
    text-align: center;
    background: var(--header-gradient);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    font-size: 2.8rem;
    font-weight: 800;
    margin-bottom: 1.5rem;
    letter-spacing: -1px;
}

.panel {
    background: var(--glass-bg);
    backdrop-filter: blur(8px);
    border: 1px solid var(--glass-border);
    border-radius: 16px;
    padding: 1.5rem;
    margin-bottom: 1.5rem;
    box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05);
}

.stButton>button {
    background: linear-gradient(180deg, #3b82f6 0%, #1d4ed8 100%);
    color: white !important;
    border: none;
    border-radius: 10px;
    padding: 0.6rem 1.2rem;
    font-weight: 600;
    transition: all 0.2s ease;
}

.stButton>button:hover {
    filter: brightness(1.1);
    box-shadow: 0 4px 12px rgba(59, 130, 246, 0.3);
    transform: translateY(-1px);
}

.security-gate {
    background: rgba(239, 68, 68, 0.05);
    border: 1px solid rgba(239, 68, 68, 0.1);
    border-radius: 12px;
    padding: 1rem;
    margin-bottom: 1rem;
}

.otc-box {
    background: #f8fafc;
    border: 1px solid #3b82f6;
    border-radius: 8px;
    padding: 0.8rem;
    text-align: center;
    font-family: 'JetBrains Mono', monospace;
    font-size: 1.4rem;
    color: #1d4ed8;
    margin: 1rem 0;
}

.stTextInput>div>div>input, .stTextArea>div>div>textarea {
    background: white !important;
    color: #1e293b !important;
    border: 1px solid #cbd5e1 !important;
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

st.markdown('<div class="header-text">CryptraQ Tactical Sender Node</div>', unsafe_allow_html=True)

# ---------- SESSION STATE ----------
_defaults = {
    "auth_step": "login",
    "failed_attempts": 0,
    "last_activity": time.time(),
    "username": None,
    "session_key": None,
    "message": "",
    "security_layer": SecurityLayer(),
    "relay_token": None,
    "relay_expiration": None,
    "relay_session_id": None,
    "hmac_tag": None,
    # PDF gate state
    "pdf_gate_open": False,
    "pdf_bytes": None,
    "pdf_otc": None,
    "pdf_filename": None,
    "encrypted_payload": None,
}
for k, v in _defaults.items():
    if k not in st.session_state:
        st.session_state[k] = v

if "session_key_input" not in st.session_state:
    st.session_state.session_key_input = st.session_state.session_key or ""

# Session Timeout check (15 mins)
if time.time() - st.session_state.last_activity > 900:
    for k in ["auth_step", "username", "failed_attempts", "pdf_gate_open", "pdf_bytes", "pdf_otc"]:
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
    st.sidebar.success("🛡️ System: READY")
else:
    st.sidebar.error("⚠️ System: OFFLINE")
    st.sidebar.caption("Run Relay Server to enable communication.")

# ---------- AUTHENTICATION FLOW ----------
if st.session_state.failed_attempts >= 3:
    st.error("🔒 Too many failed attempts. Terminal locked.")
    st.stop()

if st.session_state.auth_step == 'login':
    st.subheader("Factor 1: Credential Verification")
    user = st.text_input("Username", value="mirudula", key="login_user")
    pwd = st.text_input("Password", value="CryptraQ@SecureDefault!2026", type="password", key="login_pwd")
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

st.sidebar.title("Comm Operations")
st.sidebar.markdown(f"**Operator:** `{st.session_state.username}`")
st.sidebar.markdown(f"**Node Identity (Public Key):**\n`{st.session_state.security_layer.get_public_key_hex()}`")

if st.sidebar.button("Logout"):
    for k in list(st.session_state.keys()):
        del st.session_state[k]
    st.rerun()

# ---------- 1. QUANTUM KEY GEN ----------
st.sidebar.subheader("1. Session Key")

def generate_key_callback():
    st.session_state.session_key_input = QuantumSimulator.generate_bb84_key(32)

st.sidebar.text_input("Quantum Session Key (32-bit):", key="session_key_input")
st.session_state.session_key = st.session_state.session_key_input

st.sidebar.button("Generate Ephemeral Key", on_click=generate_key_callback)

# ---------- 2. MESSAGE INPUT ----------
st.subheader("Message Composition")

col1, col2, col3 = st.columns(3)
with col1:
    if st.button("🛑 STOP"):
        st.session_state.message = "CRITICAL STOP COMMAND"
with col2:
    if st.button("⚠️ EVACUATE"):
        st.session_state.message = "IMMEDIATE EVACUATION REQUIRED"
with col3:
    if st.button("📍 HOLD POSITION"):
        st.session_state.message = "HOLD CURRENT POSITION"

manual_msg = st.text_area("Secure Text Input", value=st.session_state.message, placeholder="Enter tactical message...")
if manual_msg != st.session_state.message:
    st.session_state.message = manual_msg

st.markdown("**Voice to Text System:**")
text = speech_to_text(language='en', use_container_width=True, just_once=True, key='STT')
if text:
    st.session_state.message = text
    st.rerun()

st.markdown("**Voice Message (Audio Recording):**")
audio = mic_recorder(
    start_prompt="⏺️ Start Recording",
    stop_prompt="⏹️ Stop Recording",
    just_once=False,
    use_container_width=True,
    key='audio_recorder',
)

if audio:
    # We store the audio bytes in session state to be sent with the packet
    st.session_state.audio_bytes = audio['bytes']
    st.audio(st.session_state.audio_bytes)
    if st.button("🗑️ Clear Recording"):
        st.session_state.audio_bytes = None
        st.rerun()
else:
    if "audio_bytes" not in st.session_state:
        st.session_state.audio_bytes = None

# ---------- 3. PACKET GENERATION ----------
st.subheader("Transmit Order")

expiration_mins = st.number_input("Packet Expiration (minutes)", min_value=1, max_value=1440, value=5)

if st.button("🚀 Encrypt & Dispatch to Relay"):
    if not st.session_state.session_key:
        st.error("Generate an Ephemeral Session Key first.")
    elif not st.session_state.message:
        st.error("Message payload cannot be empty.")
    else:
        with st.spinner("Securing Payload & Depositing..."):
            # 1. Prepare structured payload
            payload_data = {
                "text": st.session_state.message,
                "audio": None
            }
            
            if st.session_state.audio_bytes:
                import base64
                payload_data["audio"] = base64.b64encode(st.session_state.audio_bytes).decode('utf-8')
            
            payload_json = json.dumps(payload_data)

            # 2. Encrypt message
            encrypted_payload = EncryptionManager.encrypt_message(
                payload_json,
                st.session_state.session_key
            )
            st.session_state.encrypted_payload = encrypted_payload

            # 2. Sign encrypted payload (Ed25519)
            signature = st.session_state.security_layer.sign_payload(encrypted_payload)

            expiration_ts = int(time.time() + (expiration_mins * 60))
            session_id = str(uuid.uuid4())

            # 3. Assemble Packet
            packet_data = {
                "payload": encrypted_payload,
                "session_id": session_id,
                "expiration": expiration_ts,
                "signature": signature,
                "timestamp": time.time(),
                # hmac_tag added AFTER we receive the token from relay
            }

            # 4. Dispatch to Relay
            try:
                response = requests.post(f"{RELAY_URL}/deposit", json=packet_data)
                if response.status_code == 200:
                    st.success("✅ Packet Deposited in Zero-Trust Vault.")
                    res_json = response.json()
                    token = res_json['token']
                    st.session_state.relay_token = token
                    st.session_state.relay_expiration = expiration_ts
                    st.session_state.relay_session_id = session_id

                    # 5. Produce Ed25519 binding signature (token + expiration).
                    # This replaces the previous HMAC-with-public-key approach.
                    # Only the private key holder can produce a valid signature;
                    # an intercepted QR cannot be forged by a passive observer.
                    binding_sig = st.session_state.security_layer.sign_binding(
                        token=token,
                        expiration=expiration_ts,
                    )
                    st.session_state.hmac_tag = binding_sig  # stored as 'h' in QR

                    # Reset PDF gate on new dispatch
                    st.session_state.pdf_gate_open = False
                    st.session_state.pdf_bytes = None
                    st.session_state.pdf_otc = None
                else:
                    st.error(f"Relay Error: {response.text}")
            except requests.exceptions.ConnectionError:
                st.error("Could not connect to Relay Node. Is it running?")

# ---------- 4. MISSION ASSETS ----------
if st.session_state.relay_token:
    st.markdown('<div class="panel">', unsafe_allow_html=True)
    st.subheader("Mission Assets")
    st.info(f"Relay Vault Token: `{st.session_state.relay_token}`")

    # Hidden payload carries: token (t), public_key (p), session_key (k), hmac_tag (h), expiration (x), encrypted_payload (e)
    steg_payload = json.dumps({
        "t": st.session_state.relay_token,
        "p": st.session_state.security_layer.get_public_key_hex(),
        "k": st.session_state.session_key,
        "h": st.session_state.hmac_tag,
        "x": st.session_state.relay_expiration,
        "e": st.session_state.encrypted_payload,
    }).encode('utf-8')
    
    cover_image_file = st.file_uploader("Upload Cover Image (PNG/JPG) [Optional]", type=["png", "jpg", "jpeg"])
    
    if cover_image_file:
        cover_img_pil = Image.open(cover_image_file).convert('RGB')
        cover_img_array = np.array(cover_img_pil)
    else:
        st.info("Using default generated cover image...")
        cover_img_array = SteganographyManager.create_default_cover()
        
    try:
        embedded_img_array = SteganographyManager.embed_data(cover_img_array, steg_payload)
        # Encode as JPEG using the manager's controlled quality settings
        jpeg_bytes = SteganographyManager.to_jpeg_bytes(embedded_img_array)
        # Re-open from JPEG bytes so the preview matches exactly what the receiver gets
        embedded_img_pil = Image.open(BytesIO(jpeg_bytes)).convert('RGB')
        
        st.image(
            embedded_img_pil,
            caption=(
                "🔐 Mission Image (JPEG) — Carries covert payload: Token + Public Key + Binding Sig + Expiry.\n"
                "✅ Receiver node will extract and auto-fill metadata. (Session Key not included)"
            ),
            width=400
        )
        
        token_prefix = st.session_state.relay_token[:8]
        st.download_button(
            label="🖼️ Download Covert Mission Image (JPEG)",
            data=jpeg_bytes,
            file_name=f"mission_{token_prefix}.jpg",
            mime="image/jpeg"
        )
        
        st.success(
            "✨ **Mission Ready:** Download the JPEG image above and transmit it to the receiver. "
            "Remember to transmit the Session Key out-of-band."
        )
    except Exception as e:
        st.error(f"Failed to generate steganographic image: {e}")

    st.markdown("---")

    # ── Encrypted PDF Export with Re-Authentication Gate ──────────────────
    st.subheader("🔐 Export Encrypted Mission PDF")
    st.markdown(
        "**Access Control:** Re-authentication is required before generating the encrypted mission PDF. "
        "The PDF will be password-protected (AES-256 via pikepdf). Opening it requires your password."
    )

    if not st.session_state.pdf_gate_open:
        st.markdown('<div class="security-gate">', unsafe_allow_html=True)
        st.markdown("#### 🔒 Security Gate: Re-Authenticate to Export PDF")
        st.caption("Enter your login password to confirm identity before PDF generation is permitted.")

        reauth_pwd = st.text_input(
            "Confirm Password",
            value="CryptraQ@SecureDefault!2026",
            type="password",
            key="pdf_reauth_pwd",
            placeholder="Re-enter your login password..."
        )

        if st.button("✅ Verify & Generate Encrypted PDF"):
            if not reauth_pwd:
                st.error("Password cannot be empty.")
            elif not db.verify_user(st.session_state.username, reauth_pwd):
                st.session_state.failed_attempts += 1
                st.error(f"❌ Authentication Failed. Attempt {st.session_state.failed_attempts}/3.")
                if st.session_state.failed_attempts >= 3:
                    st.error("Terminal locked due to repeated failures.")
                    st.stop()
            else:
                with st.spinner("Generating AES-256 encrypted mission PDF..."):
                    try:
                        pdf_bytes, otc = build_encrypted_mission_pdf(
                            token=st.session_state.relay_token,
                            public_key_hex=st.session_state.security_layer.get_public_key_hex(),
                            hmac_tag=st.session_state.hmac_tag,
                            expiration=st.session_state.relay_expiration,
                            session_id=st.session_state.relay_session_id,
                            session_key=st.session_state.session_key,
                            user_password=reauth_pwd,
                            encrypted_payload=st.session_state.encrypted_payload,
                        )
                        st.session_state.pdf_gate_open = True
                        st.session_state.pdf_bytes = pdf_bytes
                        st.session_state.pdf_otc = otc
                        st.session_state.pdf_filename = f"mission_{st.session_state.relay_token[:8]}_enc.pdf"
                        st.success("✅ Encrypted PDF generated. Download below.")
                        st.rerun()
                    except Exception as e:
                        st.error(f"PDF generation failed: {e}")

        st.markdown('</div>', unsafe_allow_html=True)

    else:
        # Gate passed — show download + OTC
        st.success("✅ Identity Verified. Encrypted PDF Ready.")

        if st.session_state.pdf_otc:
            st.markdown("#### One-Time Unlock Code (OTC)")
            st.markdown(
                "This code is derived from your password and token. It is shown **once only** and is **never stored**. "
                "Share it with the receiver as an additional verification reference if needed."
            )
            st.markdown(
                f'<div class="otc-box">🔑 {st.session_state.pdf_otc}</div>',
                unsafe_allow_html=True
            )
            st.caption("⚠️ This code disappears when you navigate away. Note it now.")

        st.download_button(
            label="📄 Download Encrypted Mission PDF (AES-256 Protected)",
            data=st.session_state.pdf_bytes,
            file_name=st.session_state.pdf_filename,
            mime="application/pdf",
            help="This PDF is password-protected. You will need your login password to open it."
        )

        st.info(
            "📌 **To open this PDF:** Use any PDF reader and enter your login password when prompted.\n\n"
            "📌 **Session Key:** NOT included in the PDF. Transmit it out-of-band."
        )

        if st.button("🔄 Revoke PDF Access (Re-lock)"):
            st.session_state.pdf_gate_open = False
            st.session_state.pdf_bytes = None
            st.session_state.pdf_otc = None
            st.rerun()

    st.markdown('</div>', unsafe_allow_html=True)
