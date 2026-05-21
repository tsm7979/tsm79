#!/usr/bin/env bash
# ==============================================================================
# install.sh — Production installation of TSM on a Linux host
#
# Installs all TSM components from a pre-built release artifact:
#   - Creates tsm system user
#   - Copies binaries and JAR
#   - Installs systemd units
#   - Sets up PostgreSQL database (runs Flyway migrations via psql)
#   - Bootstraps secrets from Vault (calls secrets-bootstrap.sh)
#   - Enables and starts all services
#
# Usage:
#   sudo ./install.sh [--release-dir DIR] [--skip-db] [--skip-secrets] [--help]
#
# Release artifact layout:
#   release/
#     bin/tsm-dataplane          (Rust binary)
#     bin/tsm-detector           (Python launcher)
#     bin/tsm_loader             (C eBPF loader)
#     lib/tsm_xdp.o              (compiled BPF object)
#     lib/admin-api.jar          (Java Spring Boot fat JAR)
#     migrations/                (SQL migration files V001-V006)
#     systemd/                   (*.service, *.target)
# ==============================================================================
set -euo pipefail

RELEASE_DIR="${RELEASE_DIR:-./release}"
SKIP_DB=false
SKIP_SECRETS=false
TSM_USER=tsm
TSM_GROUP=tsm
CONFIG_DIR=/etc/tsm
LOG_DIR=/var/log/tsm
LIB_DIR=/usr/local/lib/tsm
BIN_DIR=/usr/local/bin
SBIN_DIR=/usr/local/sbin
SYSTEMD_DIR=/etc/systemd/system
DATA_DIR=/var/lib/tsm

log()   { echo "[install] INFO  $*"; }
warn()  { echo "[install] WARN  $*" >&2; }
error() { echo "[install] ERROR $*" >&2; }
die()   { error "$*"; exit 1; }

# ── Arguments ─────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --release-dir)  RELEASE_DIR="$2"; shift 2 ;;
        --skip-db)      SKIP_DB=true;     shift ;;
        --skip-secrets) SKIP_SECRETS=true; shift ;;
        --help|-h)
            grep '^#' "$0" | head -25 | sed 's/^# \?//'
            exit 0
            ;;
        *) die "Unknown argument: $1" ;;
    esac
done

[[ "$(id -u)" == "0" ]] || die "Must run as root"
[[ -d "$RELEASE_DIR" ]] || die "Release directory not found: $RELEASE_DIR"

# ── System user ────────────────────────────────────────────────────────────────
if ! id "$TSM_USER" &>/dev/null; then
    log "Creating system user $TSM_USER"
    useradd --system --no-create-home --shell /sbin/nologin \
            --comment "TSM Service Account" "$TSM_USER"
fi

# ── Directories ────────────────────────────────────────────────────────────────
log "Creating directories"
for d in "$CONFIG_DIR" "$LOG_DIR" "$LIB_DIR" "$DATA_DIR/dataplane" "$DATA_DIR/detector"; do
    mkdir -p "$d"
done
chown -R "$TSM_USER:$TSM_GROUP" "$LOG_DIR" "$DATA_DIR"
chmod 750 "$CONFIG_DIR"

# ── Binaries ───────────────────────────────────────────────────────────────────
log "Installing binaries"
install -m 0755 -o root -g root "$RELEASE_DIR/bin/tsm-dataplane" "$BIN_DIR/"
install -m 0755 -o root -g root "$RELEASE_DIR/bin/tsm-detector"  "$BIN_DIR/"
install -m 0755 -o root -g root "$RELEASE_DIR/bin/tsm_loader"    "$SBIN_DIR/"
install -m 0644 -o root -g root "$RELEASE_DIR/lib/tsm_xdp.o"     "$LIB_DIR/"
install -m 0644 -o root -g root "$RELEASE_DIR/lib/admin-api.jar"  "$LIB_DIR/"

# ── Default config files (do not overwrite existing) ──────────────────────────
for f in ai_cidrs.txt; do
    if [[ ! -f "$CONFIG_DIR/$f" ]]; then
        install -m 0640 -o root -g "$TSM_GROUP" "$RELEASE_DIR/config/$f" "$CONFIG_DIR/"
        log "Installed default config: $CONFIG_DIR/$f"
    else
        log "Skipping existing config: $CONFIG_DIR/$f"
    fi
done

# ── systemd units ─────────────────────────────────────────────────────────────
log "Installing systemd units"
for unit in tsm-dataplane.service tsm-detector.service tsm-loader.service tsm-admin.service tsm.target; do
    install -m 0644 -o root -g root "$RELEASE_DIR/systemd/$unit" "$SYSTEMD_DIR/"
done
systemctl daemon-reload
log "systemd units installed and daemon reloaded"

# ── PostgreSQL database setup ──────────────────────────────────────────────────
if ! $SKIP_DB; then
    log "Running PostgreSQL migrations"
    PG_SUPERUSER="${PG_SUPERUSER:-postgres}"

    # Create tsm role and database if they don't exist
    sudo -u "$PG_SUPERUSER" psql -tc \
        "SELECT 1 FROM pg_roles WHERE rolname='tsm'" | grep -q 1 || \
        sudo -u "$PG_SUPERUSER" psql -c "CREATE ROLE tsm LOGIN;"

    sudo -u "$PG_SUPERUSER" psql -tc \
        "SELECT 1 FROM pg_database WHERE datname='tsm'" | grep -q 1 || \
        sudo -u "$PG_SUPERUSER" psql -c "CREATE DATABASE tsm OWNER tsm;"

    # Run migrations in order
    for migration in "$RELEASE_DIR/migrations"/V*.sql; do
        log "Applying migration: $(basename "$migration")"
        sudo -u "$PG_SUPERUSER" psql -d tsm -f "$migration"
    done
    log "Migrations complete"
fi

# ── Secrets bootstrap ──────────────────────────────────────────────────────────
if ! $SKIP_SECRETS; then
    log "Bootstrapping secrets from Vault"
    if [[ -f "$CONFIG_DIR/vault-role-id" && -f "$CONFIG_DIR/vault-secret-id" ]]; then
        bash "$(dirname "$0")/secrets-bootstrap.sh" || warn "Secret bootstrap failed — start services manually after configuring secrets"
    else
        warn "Vault credentials not found at $CONFIG_DIR/vault-{role-id,secret-id}"
        warn "Create these files and run: sudo $CONFIG_DIR/../scripts/secrets-bootstrap.sh"
        warn "Or manually create $CONFIG_DIR/dataplane.env and $CONFIG_DIR/admin-api.env"
    fi
fi

# ── Enable and start services ──────────────────────────────────────────────────
log "Enabling TSM services"
systemctl enable tsm-loader.service tsm-detector.service tsm-dataplane.service tsm-admin.service tsm.target

if [[ -f "$CONFIG_DIR/dataplane.env" ]]; then
    log "Starting TSM services"
    systemctl start tsm.target
    sleep 3
    systemctl status tsm-dataplane.service --no-pager || true
else
    warn "Env files missing — services enabled but NOT started"
    warn "Run secrets-bootstrap.sh then: systemctl start tsm.target"
fi

log "Installation complete"
log "  Dataplane: http://localhost:8080/health"
log "  Admin API: http://localhost:9090/actuator/health"
