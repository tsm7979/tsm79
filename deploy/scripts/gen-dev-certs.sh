#!/usr/bin/env bash
##############################################################################
# gen-dev-certs.sh — Generate self-signed TLS certs for local development.
#
# Usage:
#   ./deploy/scripts/gen-dev-certs.sh [output-dir]
#
# Default output: ./nginx_certs (matches the nginx_certs Docker volume mount)
#
# Production note:
#   Replace the generated certs with real ones from Let's Encrypt or your CA:
#     certbot certonly --standalone -d your.domain.com
#     cp /etc/letsencrypt/live/your.domain.com/fullchain.pem ./nginx_certs/tls.crt
#     cp /etc/letsencrypt/live/your.domain.com/privkey.pem   ./nginx_certs/tls.key
##############################################################################
set -euo pipefail

CERT_DIR="${1:-./nginx_certs}"
mkdir -p "$CERT_DIR"

DAYS=825    # ~2.25 years (Apple ATS max for dev certs)
BITS=4096
SUBJ="/C=US/ST=Dev/L=Dev/O=TSM-Enterprise/CN=localhost"

SAN="subjectAltName=DNS:localhost,DNS:tsm.local,IP:127.0.0.1,IP:::1"

echo "[gen-dev-certs] Generating ${BITS}-bit RSA key..."
openssl genrsa -out "${CERT_DIR}/tls.key" ${BITS} 2>/dev/null

echo "[gen-dev-certs] Generating self-signed cert (${DAYS} days)..."
openssl req -new -x509 \
    -key     "${CERT_DIR}/tls.key" \
    -out     "${CERT_DIR}/tls.crt" \
    -days    ${DAYS} \
    -subj    "${SUBJ}" \
    -addext  "${SAN}" \
    2>/dev/null

chmod 600 "${CERT_DIR}/tls.key"
chmod 644 "${CERT_DIR}/tls.crt"

echo "[gen-dev-certs] Done."
echo "  cert: ${CERT_DIR}/tls.crt"
echo "  key:  ${CERT_DIR}/tls.key"
echo ""
echo "  Subject:     $(openssl x509 -noout -subject -in ${CERT_DIR}/tls.crt)"
echo "  Expires:     $(openssl x509 -noout -enddate -in ${CERT_DIR}/tls.crt)"
echo ""
echo "  Mount into Docker volume before starting the stack:"
echo "    docker run --rm -v \$(pwd)/nginx_certs:/certs alpine sh -c \\"
echo "      'cp /certs/tls.crt /certs/tls.key /etc/nginx/certs/'"
echo ""
echo "  Or copy to the named volume directly:"
echo "    docker volume create tsm_nginx_certs"
echo "    docker run --rm \\"
echo "      -v \$(pwd)/nginx_certs:/src:ro \\"
echo "      -v tsm_nginx_certs:/dst \\"
echo "      alpine cp /src/tls.crt /src/tls.key /dst/"
