# 🚀 Render.com Public Deployment Guide — CryptraQ Project

This document provides step-by-step instructions for publicly deploying the **CryptraQ** Quantum Security Stack on [Render.com](https://render.com).

---

## 📂 Deployment Files Created in Workspace

The project is now fully pre-configured for public deployment with the following files:

1. **`requirements.txt`**: Contains all required Python dependencies with headless OpenCV (`opencv-python-headless`) for Linux cloud environments.
2. **`render.yaml`**: Automated Render Blueprint specification file to deploy the entire multi-service architecture with 1-click.
3. **`Procfile`**: Defines web service process commands.
4. **`.gitignore`**: Excludes temporary files, caches, and SQLite databases from Git tracking.

---

## ⚡ Option 1: Automatic Blueprint Deployment (Recommended)

1. Push your project repository to **GitHub** or **GitLab**.
2. Log in to your [Render Dashboard](https://dashboard.render.com/).
3. Click **Blueprints** in the top navigation bar.
4. Click **New Blueprint Instance**.
5. Connect your GitHub/GitLab repository.
6. Render will automatically detect `render.yaml` and configure all 3 services:
   - **`cryptraq-relay`**: FastAPI Zero-Trust Vault Backend (Port dynamic via `$PORT`).
   - **`cryptraq-sender`**: Streamlit Tactical Sender UI.
   - **`cryptraq-receiver`**: Streamlit Tactical Receiver UI.
7. Click **Apply**. Render will automatically build and deploy all services!

---

## 🛠️ Option 2: Manual Web Service Deployment on Render

If you prefer to deploy services individually:

### 1️⃣ Deploy the Relay Server (FastAPI Backend)
- **Service Type:** Web Service
- **Name:** `cryptraq-relay`
- **Environment:** `Python 3`
- **Build Command:** `pip install -r requirements.txt`
- **Start Command:** `uvicorn cryptraq.relay_server:app --host 0.0.0.0 --port $PORT`
- **Environment Variables:**
  - `ALLOWED_ORIGINS` = `*`
  - `CRYPTRAQ_ADMIN_USER` = `mirudula` (or custom username)
  - `CRYPTRAQ_ADMIN_PASSWORD` = `CryptraQ@SecureDefault!2026` (or custom password)

*Note down your Relay service URL once deployed (e.g. `https://cryptraq-relay.onrender.com`).*

---

### 2️⃣ Deploy the Sender App (Streamlit Frontend)
- **Service Type:** Web Service
- **Name:** `cryptraq-sender`
- **Environment:** `Python 3`
- **Build Command:** `pip install -r requirements.txt`
- **Start Command:** `streamlit run cryptraq/sender_app.py --server.port $PORT --server.address 0.0.0.0`
- **Environment Variables:**
  - `RELAY_URL` = `https://cryptraq-relay.onrender.com` (Replace with your actual Relay URL)

---

### 3️⃣ Deploy the Receiver App (Streamlit Frontend)
- **Service Type:** Web Service
- **Name:** `cryptraq-receiver`
- **Environment:** `Python 3`
- **Build Command:** `pip install -r requirements.txt`
- **Start Command:** `streamlit run cryptraq/receiver_app.py --server.port $PORT --server.address 0.0.0.0`
- **Environment Variables:**
  - `RELAY_URL` = `https://cryptraq-relay.onrender.com` (Replace with your actual Relay URL)

---

## 🔍 Verification & Features

- **Environment-Aware Relay URL:** In both Streamlit apps (Sender and Receiver), the sidebar allows viewing and dynamically switching the `Relay Server URL`.
- **CORS Handling:** The FastAPI Relay Server automatically accepts requests from your deployed Streamlit domains.
- **Headless Compatibility:** Uses `opencv-python-headless` so video/image steganography processing runs smoothly in Render's headless container environment without `libGL` crashes.
