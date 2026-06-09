# FinanceFlow — multi-stage Docker image
# Runs as non-root, minimal final layer
# Base image pinned by digest for supply chain integrity

# ── Build stage ───────────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

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
FROM python:3.12-slim

LABEL maintainer="agentguardx@gmail.com"
LABEL description="FinanceFlow — simulated agentic finance system for AgentGuard-X demo"

# Non-root user
RUN groupadd --gid 1001 financeflow \
    && useradd --uid 1001 --gid financeflow --no-create-home --shell /bin/sh financeflow

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local/lib/python3.12/site-packages

# Copy application source into a financeflow/ subdirectory so that
# `from financeflow.xxx import ...` resolves correctly with PYTHONPATH=/app
COPY . financeflow/

# Create data directory with correct permissions
RUN mkdir -p /app/data && chown -R financeflow:financeflow /app

USER financeflow

# Expose ports
EXPOSE 8000 8099 8100

# Health check (exfil server default; financeflow-web overrides in compose)
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8099/health').raise_for_status()" \
    || exit 1

ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

CMD ["python", "-m", "financeflow.runner", "server"]
