FROM python:3.11-slim

# System libs needed by opencv-python-headless, PyMuPDF, pikepdf
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libgl1 \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Default command is overridden per-service in docker-compose.yml
CMD ["uvicorn", "cryptraq.relay_server:app", "--host", "0.0.0.0", "--port", "8000"]
