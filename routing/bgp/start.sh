#!/usr/bin/env bash
##############################################################################
# TSM BGP Anycast Router — ExaBGP Startup Script
#
# Substitutes environment variables into exabgp.conf before launching ExaBGP.
# Required vars (set in /etc/tsm/bgp.env or shell environment):
#
#   TSM_ROUTER_ID       — router-id (e.g. 10.0.0.1)
#   TSM_BGP_LOCAL_AS    — local AS number (e.g. 65000)
#   TSM_BGP_PEER_1_IP   — peer 1 IP address (e.g. 10.0.0.254)
#   TSM_BGP_PEER_1_AS   — peer 1 AS number (e.g. 65001)
#   TSM_BGP_NEXT_HOP    — next-hop IP for announced routes
#
# Usage:
#   sudo ./start.sh           # production
#   ./start.sh --dry-run      # validate config without starting ExaBGP
#
# Architecture:
#   ExaBGP reads exabgp.conf (after env-var substitution) and connects
#   to upstream BGP peers.  exabgp_process.py is spawned as a helper
#   process that writes ANNOUNCE/WITHDRAW commands to ExaBGP's stdin
#   based on AI provider CIDR health probes.
#
#   The effect: traffic destined for OpenAI/Anthropic CIDRs is routed
#   through the TSM node first (via policy routing + TPROXY), inspected
#   by the AI firewall, then forwarded upstream — all without Cloudflare.
##############################################################################

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONF_TEMPLATE="${SCRIPT_DIR}/exabgp.conf"
CONF_RENDERED="${SCRIPT_DIR}/exabgp.rendered.conf"
DRY_RUN=false

# ── Parse flags ───────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run) DRY_RUN=true; shift ;;
        *) echo "Unknown arg: $1" >&2; exit 1 ;;
    esac
done

# ── Source optional env file ──────────────────────────────────────────────────
if [[ -f /etc/tsm/bgp.env ]]; then
    # shellcheck disable=SC1091
    source /etc/tsm/bgp.env
fi

# ── Validate required variables ───────────────────────────────────────────────
required_vars=(
    TSM_ROUTER_ID
    TSM_BGP_LOCAL_AS
    TSM_BGP_PEER_1_IP
    TSM_BGP_PEER_1_AS
    TSM_BGP_NEXT_HOP
)

missing=()
for v in "${required_vars[@]}"; do
    if [[ -z "${!v:-}" ]]; then
        missing+=("$v")
    fi
done

if [[ ${#missing[@]} -gt 0 ]]; then
    echo "ERROR: Missing required environment variables:" >&2
    printf '  %s\n' "${missing[@]}" >&2
    echo "" >&2
    echo "Set them in /etc/tsm/bgp.env or export them before running this script." >&2
    exit 1
fi

# ── Render config from template ───────────────────────────────────────────────
echo "[bgp] Rendering exabgp.conf..."
echo "[bgp]   router-id    = ${TSM_ROUTER_ID}"
echo "[bgp]   local-as     = ${TSM_BGP_LOCAL_AS}"
echo "[bgp]   peer-1       = ${TSM_BGP_PEER_1_IP} (AS${TSM_BGP_PEER_1_AS})"
echo "[bgp]   next-hop     = ${TSM_BGP_NEXT_HOP}"

# Substitute all ${VAR} patterns in the template
sed \
    -e "s|\${TSM_ROUTER_ID}|${TSM_ROUTER_ID}|g" \
    -e "s|\${TSM_BGP_LOCAL_AS}|${TSM_BGP_LOCAL_AS}|g" \
    -e "s|\${TSM_BGP_PEER_1_IP}|${TSM_BGP_PEER_1_IP}|g" \
    -e "s|\${TSM_BGP_PEER_1_AS}|${TSM_BGP_PEER_1_AS}|g" \
    -e "s|\${TSM_BGP_NEXT_HOP}|${TSM_BGP_NEXT_HOP}|g" \
    "${CONF_TEMPLATE}" > "${CONF_RENDERED}"

chmod 600 "${CONF_RENDERED}"
echo "[bgp] Config written to ${CONF_RENDERED}"

# ── Validate with ExaBGP ──────────────────────────────────────────────────────
if ! command -v exabgp &>/dev/null; then
    echo "ERROR: exabgp not found. Install with: pip install exabgp" >&2
    exit 1
fi

echo "[bgp] Validating config..."
if ! exabgp --validate "${CONF_RENDERED}" 2>&1; then
    echo "ERROR: exabgp config validation failed." >&2
    rm -f "${CONF_RENDERED}"
    exit 1
fi
echo "[bgp] Config valid."

if [[ "$DRY_RUN" == "true" ]]; then
    echo "[bgp] Dry-run complete. Not starting ExaBGP."
    exit 0
fi

# ── Configure policy routing ──────────────────────────────────────────────────
# Set up the policy routing table that TPROXY uses.
# Table 100: all AI CIDR traffic is redirected via the TPROXY rule.
echo "[bgp] Configuring policy routing table 100..."
ip rule add fwmark 0xfee1dead table 100 priority 100 2>/dev/null || true
ip route add local default dev lo table 100 2>/dev/null || true
echo "[bgp] Policy routing configured."

# ── Start ExaBGP ─────────────────────────────────────────────────────────────
echo "[bgp] Starting ExaBGP..."
exec env \
    exabgp_cli_pipe_size=1048576 \
    exabgp_log_all=true \
    exabgp_daemon=false \
    exabgp "${CONF_RENDERED}"
