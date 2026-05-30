#!/usr/bin/env bash
# ==============================================================================
# secrets-bootstrap.sh — Fetch secrets from Vault and write env files
#
# Reads secrets from HashiCorp Vault KV v2 and writes them to
# /etc/tsm/{dataplane,detector,admin-api}.env  (chmod 600, owned by tsm:tsm).
#
# Vault authentication: AppRole (Role ID from /etc/tsm/vault-role-id,
#                                Secret ID from /etc/tsm/vault-secret-id)
#
# Run as root during initial provisioning and on secret rotation.
#
# Usage:
#   sudo ./secrets-bootstrap.sh [--vault-addr ADDR] [--mount-path PATH]
#                               [--dry-run] [--help]
#
# Environment:
#   VAULT_ADDR       Vault server URL (default: https://vault.internal:8200)
#   VAULT_MOUNT      KV mount path    (default: secret)
#   VAULT_ROLE_ID    AppRole role ID  (overrides /etc/tsm/vault-role-id)
#   VAULT_SECRET_ID  AppRole secret ID (overrides /etc/tsm/vault-secret-id)
# ==============================================================================
set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
VAULT_ADDR="${VAULT_ADDR:-https://vault.internal:8200}"
VAULT_MOUNT="${VAULT_MOUNT:-secret}"
TSM_CONFIG_DIR="/etc/tsm"
TSM_USER="tsm"
DRY_RUN=false
LOG_TAG="secrets-bootstrap"

# ── Logging ───────────────────────────────────────────────────────────────────
log()   { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] [$LOG_TAG] INFO  $*" >&2; }
warn()  { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] [$LOG_TAG] WARN  $*" >&2; }
error() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] [$LOG_TAG] ERROR $*" >&2; }
die()   { error "$*"; exit 1; }

# ── Argument parsing ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --vault-addr)   VAULT_ADDR="$2";  shift 2 ;;
        --mount-path)   VAULT_MOUNT="$2"; shift 2 ;;
        --dry-run)      DRY_RUN=true;     shift   ;;
        --help|-h)
            grep '^#' "$0" | head -30 | sed 's/^# \?//'
            exit 0
            ;;
        *) die "Unknown argument: $1" ;;
    esac
done

# ── Pre-flight checks ─────────────────────────────────────────────────────────
[[ "$(id -u)" == "0" ]] || die "Must run as root"
command -v curl  &>/dev/null || die "curl is required"
command -v jq    &>/dev/null || die "jq is required"

# ── Vault AppRole authentication ──────────────────────────────────────────────
ROLE_ID="${VAULT_ROLE_ID:-}"
SECRET_ID="${VAULT_SECRET_ID:-}"

if [[ -z "$ROLE_ID" ]]; then
    [[ -f "$TSM_CONFIG_DIR/vault-role-id" ]] || die "Vault role ID not found at $TSM_CONFIG_DIR/vault-role-id"
    ROLE_ID="$(cat "$TSM_CONFIG_DIR/vault-role-id")"
fi

if [[ -z "$SECRET_ID" ]]; then
    [[ -f "$TSM_CONFIG_DIR/vault-secret-id" ]] || die "Vault secret ID not found at $TSM_CONFIG_DIR/vault-secret-id"
    SECRET_ID="$(cat "$TSM_CONFIG_DIR/vault-secret-id")"
fi

log "Authenticating to Vault at $VAULT_ADDR"

VAULT_TOKEN="$(
    curl --silent --fail \
        -X POST "$VAULT_ADDR/v1/auth/approle/login" \
        -H "Content-Type: application/json" \
        -d "{\"role_id\":\"$ROLE_ID\",\"secret_id\":\"$SECRET_ID\"}" \
    | jq -r '.auth.client_token'
)"

[[ -n "$VAULT_TOKEN" && "$VAULT_TOKEN" != "null" ]] || die "Vault authentication failed"
log "Vault authentication successful"

# ── Helper: read a Vault KV v2 secret ────────────────────────────────────────
vault_get() {
    local path="$1"
    curl --silent --fail \
        -H "X-Vault-Token: $VAULT_TOKEN" \
        "$VAULT_ADDR/v1/$VAULT_MOUNT/data/$path" \
    | jq -r '.data.data'
}

vault_field() {
    local path="$1"
    local field="$2"
    vault_get "$path" | jq -r ".[\"$field\"]"
}

# ── Helper: write env file ────────────────────────────────────────────────────
write_env_file() {
    local dest="$1"
    local content="$2"

    if $DRY_RUN; then
        log "[DRY RUN] Would write $dest:"
        echo "$content" | sed 's/=.*/=<REDACTED>/'
        return
    fi

    local tmp
    tmp="$(mktemp "$TSM_CONFIG_DIR/.tmp.XXXXXX")"
    echo "$content" > "$tmp"
    chmod 600 "$tmp"
    chown "$TSM_USER:$TSM_USER" "$tmp" 2>/dev/null || true
    mv "$tmp" "$dest"
    chmod 600 "$dest"
    chown "$TSM_USER:$TSM_USER" "$dest" 2>/dev/null || true
    log "Written $dest"
}

# ── Fetch secrets from Vault ──────────────────────────────────────────────────
log "Fetching tsm/dataplane secrets"
DP_SECRETS="$(vault_get "tsm/dataplane")"
DP_PG_DSN="$(echo "$DP_SECRETS" | jq -r '.pg_dsn')"
DP_AUDIT_SECRET="$(echo "$DP_SECRETS" | jq -r '.audit_secret')"
DP_CONTROL_PLANE="$(echo "$DP_SECRETS" | jq -r '.control_plane_url')"
DP_KAFKA="$(echo "$DP_SECRETS" | jq -r '.kafka_brokers // ""')"
DP_POLICY_PUBKEY="$(echo "$DP_SECRETS" | jq -r '.policy_pubkey_b64 // ""')"
DP_WORKSPACE_ID="$(echo "$DP_SECRETS" | jq -r '.workspace_id // "00000000-0000-0000-0000-000000000002"')"
DP_ORG_ID="$(echo "$DP_SECRETS" | jq -r '.org_id // "00000000-0000-0000-0000-000000000001"')"

log "Fetching tsm/admin-api secrets"
ADM_SECRETS="$(vault_get "tsm/admin-api")"
ADM_PG_URL="$(echo "$ADM_SECRETS" | jq -r '.pg_url')"
ADM_PG_USER="$(echo "$ADM_SECRETS" | jq -r '.pg_user')"
ADM_PG_PASS="$(echo "$ADM_SECRETS" | jq -r '.pg_password')"
ADM_JWT_SECRET="$(echo "$ADM_SECRETS" | jq -r '.jwt_secret')"

# ── Write env files ───────────────────────────────────────────────────────────
write_env_file "$TSM_CONFIG_DIR/dataplane.env" "
# TSM Dataplane secrets — generated by secrets-bootstrap.sh
# DO NOT EDIT MANUALLY — re-run secrets-bootstrap.sh to rotate
TSM_PG_DSN=${DP_PG_DSN}
TSM_AUDIT_SECRET=${DP_AUDIT_SECRET}
TSM_CONTROL_PLANE_URL=${DP_CONTROL_PLANE}
TSM_KAFKA_BROKERS=${DP_KAFKA}
TSM_POLICY_PUBKEY_B64=${DP_POLICY_PUBKEY}
TSM_WORKSPACE_ID=${DP_WORKSPACE_ID}
TSM_ORG_ID=${DP_ORG_ID}
"

write_env_file "$TSM_CONFIG_DIR/admin-api.env" "
# TSM Admin API secrets — generated by secrets-bootstrap.sh
TSM_PG_URL=${ADM_PG_URL}
TSM_PG_USER=${ADM_PG_USER}
TSM_PG_PASSWORD=${ADM_PG_PASS}
TSM_JWT_SECRET=${ADM_JWT_SECRET}
"

# ── Revoke the short-lived Vault token ───────────────────────────────────────
curl --silent \
    -X POST "$VAULT_ADDR/v1/auth/token/revoke-self" \
    -H "X-Vault-Token: $VAULT_TOKEN" \
    >/dev/null 2>&1 || true
log "Vault token revoked"

# ── Reload services (if already running) ─────────────────────────────────────
if ! $DRY_RUN; then
    for svc in tsm-dataplane tsm-admin; do
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            log "Reloading $svc..."
            systemctl reload-or-restart "$svc" || warn "Failed to restart $svc"
        fi
    done
fi

log "Secret bootstrap complete"
