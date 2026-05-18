# Use a lightweight official Python 3.10 base image
FROM python:3.10-slim

# Set strict system paths and environment variables
ENV PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive \
    SSOL_DEMO_MODE=1

# Install base system diagnostic tools and dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
    procps \
    netcat-openbsd \
    lvm2 \
    curl \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Establish working directory paths
WORKDIR /usr/local/share/ssol

# Copy dependencies manifest first to utilize layer caching
COPY requirements.txt .

# Install python libraries (fallback package installations ignored if torch-geometric is heavy)
RUN pip install --no-cache-dir -r requirements.txt || \
    pip install --no-cache-dir PyYAML PyJWT Flask scapy

# Copy entire codebase to share directory
COPY . .

# Copy pre-flight healthcheck validation script to bin path
RUN cp ssol_health_check.sh /usr/local/bin/ssol_health_check.sh && \
    chmod +x /usr/local/bin/ssol_health_check.sh

# Expose ports for communication
# 5000 -> REST API / real-time glassmorphic dashboard SSE server
# 9099 -> interprocess socket communication TCP fallback
EXPOSE 5000 9099

# Set default start command executing health checks and main daemon orchestrator
ENTRYPOINT ["/bin/bash", "-c", "/usr/local/bin/ssol_health_check.sh --mock && python3 ssol_daemon.py"]
