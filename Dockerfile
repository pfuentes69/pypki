FROM python:3.13-slim

# System dependencies needed to build mysql-connector-python and pykcs11.
# softhsm2 + opensc provide a software PKCS#11 token for HSM development and
# `pkcs11-tool` for inspection; both are small and harmless if the HSM path
# is not used at runtime.
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        pkg-config \
        libmariadb-dev \
        openssl \
        softhsm2 \
        opensc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies first (layer is cached unless requirements change)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY pypki/   pypki/
COPY web/     web/
COPY utils/   utils/
COPY config/  config/

# Entrypoint handles first-run DB init then starts gunicorn
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

EXPOSE 8080

ENTRYPOINT ["/docker-entrypoint.sh"]
