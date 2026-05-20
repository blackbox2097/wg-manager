FROM python:3.12-slim-bookworm

LABEL org.opencontainers.image.title="WireGuard Manager"
LABEL org.opencontainers.image.description="Self-hosted WireGuard VPN management web UI"
LABEL org.opencontainers.image.source="https://github.com/blackbox2097/wg-manager"
LABEL org.opencontainers.image.licenses="MIT"

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    wireguard-tools \
    iptables \
    iproute2 \
    procps \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps first (layer cache)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy app files
COPY app.py .
COPY gunicorn_config.py .
COPY templates/ templates/

EXPOSE 5000

# WireGuard configs and DB are persisted via volume mount
VOLUME ["/etc/wireguard"]

ENV WG_DIR=/etc/wireguard \
    WG_META_DIR=/etc/wireguard \
    WG_DB_PATH=/etc/wireguard/wg-manager.db \
    SESSION_MINUTES=30

CMD ["gunicorn", "--config", "gunicorn_config.py", "app:app"]
