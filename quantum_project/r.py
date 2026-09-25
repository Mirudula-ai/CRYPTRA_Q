import streamlit as st
from cryptography.fernet import Fernet
import base64
import cv2
import numpy as np
from PIL import Image

st.set_page_config(page_title="Quantum Receiver", layout="wide")

# ---------- UI ----------
st.markdown("""
<style>
body {
    background: linear-gradient(135deg, #141e30, #243b55);
    color: white;
}
.stButton>button {
    background: linear-gradient(90deg, #ff512f, #dd2476);
    color: white;
    border-radius: 12px;
    height: 50px;
    border: none;
}
.alert {
    background-color: #ff4d4d;
    padding: 20px;
    border-radius: 12px;
    font-weight: bold;
}
</style>
""", unsafe_allow_html=True)

st.title("📥 Quantum Secure Receiver")

# ---------- CAMERA INPUT ----------
st.subheader("📷 Scan QR using Camera")

camera_image = st.camera_input("Take a picture of QR code")

encrypted = ""

if camera_image is not None:
    image = Image.open(camera_image)
    img = np.array(image)

    detector = cv2.QRCodeDetector()
    data, bbox, _ = detector.detectAndDecode(img)

    if data:
        st.success("QR Code Detected ✅")
        encrypted = data
        st.text_area("Encrypted Message", value=encrypted)
    else:
        st.error("No QR code detected")

# ---------- Manual fallback ----------
manual = st.text_area("Or Paste Encrypted Message")

if manual:
    encrypted = manual

# ---------- KEY ----------
key = st.text_input("🔑 Enter Quantum Key")

# ---------- DECRYPT ----------
def decrypt_msg(enc, key):
    key_bytes = base64.urlsafe_b64encode(key.ljust(32).encode())
    cipher = Fernet(key_bytes)
    return cipher.decrypt(enc.encode()).decode()

if st.button("🔓 Decrypt Message"):
    try:
        msg = decrypt_msg(encrypted, key)

        if any(word in msg for word in ["STOP", "RETREAT", "ALERT", "HELP"]):
            st.markdown(f'<div class="alert">🚨 {msg}</div>', unsafe_allow_html=True)
        else:
            st.success(msg)

    except:
        st.error("Invalid key or message")