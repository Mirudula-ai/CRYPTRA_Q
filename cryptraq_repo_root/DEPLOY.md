# Deploying CryptraQ (relay + sender + receiver)

This project is three long-running services, not a single script:

- **relay** – FastAPI server (`cryptraq/relay_server.py`), stores encrypted packets, port 8000
- **sender** – Streamlit app (`cryptraq/sender_app.py`), port 8501
- **receiver** – Streamlit app (`cryptraq/receiver_app.py`), port 8502

The easiest reliable way to run all three together, anywhere, is Docker Compose —
it installs the heavy dependencies (qiskit, opencv, PyMuPDF, pikepdf) once into an
image and starts all three services wired to each other automatically.

## 1. Run it locally first (recommended before deploying anywhere)

Prerequisites: [Docker Desktop](https://www.docker.com/products/docker-desktop/) installed.

```bash
cd quantum_project
cp .env.example .env
# edit .env and set a real CRYPTRAQ_ADMIN_PASSWORD

docker compose up --build
```

Then open:
- Sender:   http://localhost:8501
- Receiver: http://localhost:8502
- Relay health check: http://localhost:8000/health

The sender and receiver both talk to the relay over the internal Docker network
(`http://relay:8000`), and all three share one SQLite database via a Docker volume,
so accounts and deposited packets are consistent across services.

Stop everything with `docker compose down` (add `-v` to also wipe the stored database).

## 2. Put it on a real server (so others can reach it)

Once step 1 works locally, deploying is the same steps on a machine with a public IP:

1. Get a small VPS (e.g. a $5–6/mo DigitalOcean/Linode/Hetzner droplet, or an AWS/GCP/Azure
   VM) running Ubuntu, and install Docker + the Compose plugin on it.
2. Copy this whole `quantum_project` folder to the server (`scp -r quantum_project user@server:~/` or `git clone` if you push it to a repo).
3. On the server: `cp .env.example .env`, set a strong `CRYPTRAQ_ADMIN_PASSWORD`, then `docker compose up -d --build`.
4. Open inbound firewall ports 8000 (relay), 8501 (sender), 8502 (receiver) — or better,
   put an Nginx/Caddy reverse proxy in front with HTTPS and only expose 443.
5. Share `http://<server-ip>:8501` with the sender and `http://<server-ip>:8502` with the
   receiver. Keep the relay (8000) reachable by both but you don't need to expose it publicly
   if sender/receiver run on the same host — you'd only open it if they run on *different*
   machines, in which case set `RELAY_URL` on each to the relay's public address.

## 3. Alternative: free-tier cloud platforms (no server to manage)

Possible, but more fiddly for this project because of the heavy scientific dependencies
(qiskit, qiskit-aer, opencv) and because it's three coordinated services rather than one app:

- **Relay** → Render.com or Railway.app "Web Service" from this repo, start command:
  `uvicorn cryptraq.relay_server:app --host 0.0.0.0 --port $PORT`
- **Sender / Receiver** → Streamlit Community Cloud, one app each, main file
  `cryptraq/sender_app.py` / `cryptraq/receiver_app.py`, with a `RELAY_URL` secret set to
  your deployed relay's public URL.
- Watch build times/memory limits on free tiers — qiskit-aer in particular is a large
  install and may exceed a free plan's build resources.

Docker Compose on a small VPS (option 2) avoids all of this and is what I'd recommend
unless you specifically want everything on free-tier platforms.

## Notes on what I changed to make this deployable

- `RELAY_URL` in `sender_app.py` / `receiver_app.py` now reads from the `RELAY_URL`
  environment variable (falls back to `http://127.0.0.1:8000` for plain local runs
  outside Docker).
- `DatabaseManager` now reads its SQLite path from `CRYPTRAQ_DB_PATH` if set, so all
  three containers can share one database file/volume.
- Added `requirements.txt`, `Dockerfile`, `docker-compose.yml`, `.env.example`.
- **Security note**: `db_manager.py` seeds a default admin user/password
  (`mirudula` / `CryptraQ@SecureDefault!2026`) if the `CRYPTRAQ_ADMIN_USER` /
  `CRYPTRAQ_ADMIN_PASSWORD` env vars aren't set — the compose file forces you to set
  a real password before it will start. Don't run this reachable from the internet
  with the default credentials.

## 3b. Free-tier deployment, step by step (Render + Streamlit Community Cloud)

This is the path that needs no server management. It uses Render for the relay
(FastAPI) and Streamlit Community Cloud for the sender and receiver apps.

**Before you start:** make `quantum_project/` itself the root of a GitHub repo
(so `requirements.txt` sits at the repo's top level) — both platforms expect that.

```bash
cd quantum_project
git init
git add .
git commit -m "CryptraQ deploy"
gh repo create cryptraq --public --source=. --push   # or push to GitHub manually
```

### Step 1 — Deploy the relay on Render
1. Go to render.com, sign in with GitHub, **New → Web Service**, pick the `cryptraq` repo.
2. Build command: `pip install -r requirements.txt`
3. Start command: `uvicorn cryptraq.relay_server:app --host 0.0.0.0 --port $PORT`
4. Instance type: **Free**
5. Add environment variables: `CRYPTRAQ_ADMIN_USER`, `CRYPTRAQ_ADMIN_PASSWORD` (pick a real password)
6. Deploy. Note the public URL Render gives you, e.g. `https://cryptraq-relay.onrender.com`
7. Confirm it's alive: open `https://cryptraq-relay.onrender.com/health` in a browser.

### Step 2 — Deploy the sender on Streamlit Community Cloud
1. Go to share.streamlit.io, sign in with GitHub, **New app**, pick the `cryptraq` repo.
2. Main file path: `cryptraq/sender_app.py`
3. Advanced settings → Secrets, add:
   ```
   RELAY_URL = "https://cryptraq-relay.onrender.com"
   CRYPTRAQ_ADMIN_USER = "mirudula"
   CRYPTRAQ_ADMIN_PASSWORD = "the-same-password-you-set-on-render"
   ```
4. Deploy. You'll get a URL like `https://<something>.streamlit.app`.

### Step 3 — Deploy the receiver the same way
Repeat step 2 as a second Streamlit app with main file path `cryptraq/receiver_app.py`
and the same secrets.

### Free-tier limits to know about
- **Render free web services sleep after ~15 min idle** and take ~30–50s to wake on
  the next request — the sender/receiver "Relay: OFFLINE" indicator will show red
  until it wakes up. This is normal, not a bug.
- **Render's free tier disk is not persistent.** When the relay service restarts
  (redeploy, or waking from sleep can trigger a fresh instance), its SQLite file —
  and anything in it, including packets deposited but not yet retrieved — can be
  reset. Fine for a demo/prototype; not fine if you need packets to reliably survive
  hours of idle time. Render's paid tier adds a persistent disk if you need that.
- **Streamlit Community Cloud** also has ephemeral storage and its app can sleep
  after inactivity; the same "wakes up slowly" behavior applies.
- Qiskit + qiskit-aer are the heaviest dependencies to build — expect the first
  deploy on each platform to take several minutes.
- `cryptraq/auth/biometrics.py` (OpenCV face recognition) isn't actually imported
  by either app, so it doesn't affect what you need to install.

## Running without Docker (e.g. quick local test)

```bash
cd quantum_project
python -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt

# terminal 1
uvicorn cryptraq.relay_server:app --host 0.0.0.0 --port 8000

# terminal 2
streamlit run cryptraq/sender_app.py --server.port 8501

# terminal 3
streamlit run cryptraq/receiver_app.py --server.port 8502
```
