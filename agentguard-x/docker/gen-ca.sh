#!/usr/bin/env bash
# Generate the mitmproxy CA certificate at runtime.
# Called by agentguard.sh up AFTER the proxy container starts.
# The CA is stored in a Docker volume — never committed to git.
#
# Usage: ./gen-ca.sh [certs_dir]
#   certs_dir: host directory to export the CA cert (default: ./certs)
#
# Output files (certs_dir/):
#   mitmproxy-ca.pem     — CA cert (public, safe to distribute to agents)
#   mitmproxy-ca-cert.pem — CA cert only (no key)
#
# The private key stays INSIDE the Docker volume (never exported).

set -euo pipefail

CERTS_DIR="${1:-$(dirname "$0")/../certs}"
CONTAINER="agentguard-proxy"

mkdir -p "${CERTS_DIR}"

echo "[gen-ca] Waiting for proxy container to generate CA..."

# mitmproxy generates its CA on first start. Poll until it exists.
for attempt in $(seq 1 30); do
    if docker exec "${CONTAINER}" test -f /home/mitmproxy/.mitmproxy/mitmproxy-ca.pem 2>/dev/null; then
        echo "[gen-ca] CA found after ${attempt} attempts."
        break
    fi
    if [ "${attempt}" -eq 30 ]; then
        echo "[gen-ca] ERROR: CA not generated after 60s. Check proxy container logs." >&2
        exit 1
    fi
    sleep 2
done

# Export the PUBLIC cert only (no private key) to certs_dir for agent trust stores
docker exec "${CONTAINER}" cat /home/mitmproxy/.mitmproxy/mitmproxy-ca-cert.pem \
    > "${CERTS_DIR}/mitmproxy-ca-cert.pem"

echo "[gen-ca] CA cert exported to: ${CERTS_DIR}/mitmproxy-ca-cert.pem"
echo "[gen-ca] Private key stays inside Docker volume (never exported)."
echo ""
echo "[gen-ca] To trust the CA in a container:"
echo "  REQUESTS_CA_BUNDLE=/path/to/mitmproxy-ca-cert.pem python ..."
echo "  or set HTTP_PROXY=http://proxy:8082"
