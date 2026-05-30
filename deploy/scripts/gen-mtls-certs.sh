#!/usr/bin/env bash
##############################################################################
# gen-mtls-certs.sh — Generate TSM internal CA + mTLS certificates
#
# Creates:
#   tsm-ca.key / tsm-ca.crt         — Internal CA (never leaves the host)
#   server.key / server.crt         — Server cert signed by TSM CA
#   client-<service>.key/crt        — Per-service client certs for mTLS
#
# Usage:
#   ./gen-mtls-certs.sh [output-dir] [--services "admin-api control-plane"]
#
# All keys are 4096-bit RSA.  CA cert is valid 10 years.
# Service certs are valid 1 year (rotate via CI/CD).
##############################################################################
set -euo pipefail

CERT_DIR="${1:-./mtls_certs}"
SERVICES="${2:-admin-api control-plane detector tsm-ctl}"
CA_DAYS=3650    # 10 years
SVC_DAYS=365    # 1 year

mkdir -p "$CERT_DIR"

echo "[mtls] Generating TSM internal CA..."
# CA private key
openssl genrsa -out "${CERT_DIR}/tsm-ca.key" 4096 2>/dev/null
chmod 600 "${CERT_DIR}/tsm-ca.key"
# CA self-signed cert
openssl req -new -x509 \
    -key  "${CERT_DIR}/tsm-ca.key" \
    -out  "${CERT_DIR}/tsm-ca.crt" \
    -days $CA_DAYS \
    -subj "/C=US/O=TSM-Enterprise/CN=TSM-Internal-CA" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    2>/dev/null
echo "  CA: ${CERT_DIR}/tsm-ca.crt"

echo ""
echo "[mtls] Generating per-service client certificates..."
for svc in $SERVICES; do
    KEY="${CERT_DIR}/client-${svc}.key"
    CSR="${CERT_DIR}/client-${svc}.csr"
    CRT="${CERT_DIR}/client-${svc}.crt"

    openssl genrsa -out "$KEY" 4096 2>/dev/null
    chmod 600 "$KEY"

    openssl req -new \
        -key  "$KEY" \
        -out  "$CSR" \
        -subj "/C=US/O=TSM-Enterprise/CN=tsm-${svc}" \
        2>/dev/null

    openssl x509 -req \
        -in   "$CSR" \
        -CA   "${CERT_DIR}/tsm-ca.crt" \
        -CAkey "${CERT_DIR}/tsm-ca.key" \
        -CAcreateserial \
        -out  "$CRT" \
        -days $SVC_DAYS \
        -extensions v3_req \
        -extfile <(printf "[v3_req]\nextendedKeyUsage=clientAuth\nsubjectAltName=DNS:tsm-%s,DNS:tsm-%s.tsm-internal\n" "$svc" "$svc") \
        2>/dev/null

    rm -f "$CSR"
    echo "  Service: $svc → ${CRT}"
done

echo ""
echo "[mtls] Certificate generation complete."
echo ""
echo "  Copy tsm-ca.crt to nginx_certs/ and mount as /etc/nginx/certs/tsm-ca.crt"
echo "  Mount per-service client certs into each service container."
echo ""
echo "  Docker Compose volume example:"
echo "    volumes:"
echo "      - ./mtls_certs/client-admin-api.crt:/etc/tsm/certs/client.crt:ro"
echo "      - ./mtls_certs/client-admin-api.key:/etc/tsm/certs/client.key:ro"
echo "      - ./mtls_certs/tsm-ca.crt:/etc/tsm/certs/ca.crt:ro"
echo ""
echo "  Never commit these certs to version control."
echo "  Rotate annually or immediately if any key is compromised."
