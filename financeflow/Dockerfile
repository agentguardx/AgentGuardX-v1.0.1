# FinanceFlow — multi-stage Docker image
# Runs as non-root, minimal final layer
# Base image pinned by digest for supply chain integrity

# ── Build stage ───────────────────────────────────────────────────────────────
FROM python:3.12-slim@sha256:b3e42b5c50cbbb116ccbbb9a52862e43e0e22e0e9f9e24fec0b6798d5eb52578 AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip==24.3.1 \
    && pip install --no-cache-dir -r requirements.txt --target /install

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM python:3.12-slim@sha256:b3e42b5c50cbbb116ccbbb9a52862e43e0e22e0e9f9e24fec0b6798d5eb52578

LABEL maintainer="agentguardx@gmail.com"
LABEL description="FinanceFlow — simulated agentic finance system for AgentGuard-X demo"

# Non-root user
RUN groupadd --gid 1001 financeflow \
    && useradd --uid 1001 --gid financeflow --no-create-home --shell /bin/sh financeflow

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local/lib/python3.12/site-packages

# Copy application source
COPY . .

# Create data directory with correct permissions
RUN mkdir -p /app/data && chown -R financeflow:financeflow /app

USER financeflow

# Expose ports
EXPOSE 8000 8099

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8099/health').raise_for_status()" \
    || exit 1

ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

CMD ["python", "runner.py", "server"]
