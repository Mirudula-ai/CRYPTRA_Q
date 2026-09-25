import streamlit as st
import numpy as np
from qiskit import QuantumCircuit, transpile
from qiskit_aer import Aer
from cryptography.fernet import Fernet
import base64
import qrcode
from io import BytesIO

st.set_page_config(page_title="Quantum Sender", layout="wide")

# ---------- UI ----------
st.markdown("""
<style>
body {
    background: linear-gradient(135deg, #0f2027, #203a43, #2c5364);
    color: white;
}
.stButton>button {
    background: linear-gradient(90deg, #00c6ff, #0072ff);
    color: white;
    border-radius: 12px;
    height: 55px;
    font-size: 15px;
    border: none;
}
.signal-box {
    background: rgba(255,255,255,0.1);
    padding: 15px;
    border-radius: 10px;
    margin-top: 10px;
}
</style>
""", unsafe_allow_html=True)

st.title("🛡️ Quantum Secure Sender")

# ---------- SESSION STATE ----------
if "msg" not in st.session_state:
    st.session_state.msg = ""

# ---------- Quantum Key ----------
def generate_key(n=16):
    sender_bits = np.random.randint(2, size=n)
    sender_bases = np.random.randint(2, size=n)
    receiver_bases = np.random.randint(2, size=n)

    backend = Aer.get_backend('qasm_simulator')
    key = []

    for i in range(n):
        qc = QuantumCircuit(1,1)

        if sender_bits[i]: qc.x(0)
        if sender_bases[i]: qc.h(0)
        if receiver_bases[i]: qc.h(0)

        qc.measure(0,0)

        compiled = transpile(qc, backend)
        job = backend.run(compiled, shots=1)
        result = job.result()

        measured = int(list(result.get_counts().keys())[0])

        if sender_bases[i] == receiver_bases[i]:
            key.append(str(measured))

    return ''.join(key)

# ---------- Encrypt ----------
def encrypt_msg(msg, key):
    key_bytes = base64.urlsafe_b64encode(key.ljust(32).encode())
    cipher = Fernet(key_bytes)
    return cipher.encrypt(msg.encode())

# ---------- EMERGENCY BUTTONS ----------
st.subheader("🚨 Emergency Signals")

col1, col2, col3, col4 = st.columns(4)

with col1:
    if st.button("🛑 STOP"):
        st.session_state.msg = "STOP IMMEDIATELY"
with col2:
    if st.button("⚠️ ALERT"):
        st.session_state.msg = "ENEMY DETECTED"
with col3:
    if st.button("🏃 RETREAT"):
        st.session_state.msg = "RETREAT NOW"
with col4:
    if st.button("👁️ AWARE"):
        st.session_state.msg = "STAY ALERT"

col5, col6, col7, col8 = st.columns(4)

with col5:
    if st.button("📍 LOCATION"):
        st.session_state.msg = "SEND LOCATION"
with col6:
    if st.button("🆘 HELP"):
        st.session_state.msg = "NEED IMMEDIATE BACKUP"
with col7:
    if st.button("🎯 TARGET"):
        st.session_state.msg = "TARGET IDENTIFIED"
with col8:
    if st.button("🔒 SECURE"):
        st.session_state.msg = "AREA SECURED"

# ---------- SHOW SELECTED ----------
if st.session_state.msg:
    st.markdown(f'<div class="signal-box">Selected Signal: {st.session_state.msg}</div>', unsafe_allow_html=True)

# ---------- CUSTOM MESSAGE ----------
user_msg = st.text_area("✉️ Or Enter Custom Message")

if user_msg:
    st.session_state.msg = user_msg

# ---------- KEY ----------
if st.button("🔑 Generate Quantum Key"):
    st.session_state.key = generate_key()
    st.success(f"Quantum Key: {st.session_state.key}")

# ---------- ENCRYPT ----------
if st.button("🔐 Generate QR"):
    if "key" not in st.session_state:
        st.error("Generate key first")
    elif st.session_state.msg == "":
        st.warning("Select or enter message")
    else:
        encrypted = encrypt_msg(st.session_state.msg, st.session_state.key)

        st.success("Encrypted Successfully")

        qr = qrcode.make(encrypted.decode('utf-8'))
        buf = BytesIO()
        qr.save(buf)

        st.image(buf.getvalue(), caption="📷 Scan this QR at Receiver")

        st.text_area("Encrypted Backup", encrypted.decode('utf-8'))