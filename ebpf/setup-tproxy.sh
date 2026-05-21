#!/usr/bin/env bash
# TSMv2 — TPROXY transparent-proxy setup for AI API interception.
#
# This script wires the kernel routing and netfilter rules that cause
# outbound TCP:443 packets marked by the eBPF tproxy hook to be
# redirected to the local TSM data plane on port 8443.
#
# Architecture (packet flow):
#
#   App calls api.openai.com:443
#       │
#       ▼ (egress — TC hook fires)
#   tproxy.c: dst_ip in ai_ips? → skb->mark = 0xfee1dead
#       │
#       ▼ (kernel routes the packet)
#   iptables OUTPUT mangle: mark 0xfee1dead → tag for NAT
#       │
#       ▼
#   iptables OUTPUT nat: REDIRECT to 127.0.0.1:8443
#       │
#       ▼
#   TSM data plane (port 8443) receives the connection
#   Recovers original dst via SO_ORIGINAL_DST
#   Performs scan → forward to real api.openai.com:443
#
# Requirements:
#   - Linux kernel ≥ 5.8 (BPF_MAP_TYPE_LPM_TRIE, clsact qdisc)
#   - iproute2, iptables
#   - TSM data plane binary must be running or will start on port 8443
#   - Must be run as root (or with CAP_NET_ADMIN + CAP_NET_RAW)
#
# Usage:
#   sudo ./setup-tproxy.sh [--iface eth0] [--proxy-port 8443] [--teardown]
#
# Environment variables (override defaults):
#   TSM_IFACE       network interface to attach TC hook (default: auto-detect)
#   TSM_PROXY_PORT  local port TSM data plane listens on (default: 8443)
#   TSM_BPF_OBJ     path to compiled tproxy.o (default: ./tproxy.o)

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
PROXY_PORT="${TSM_PROXY_PORT:-8443}"
BPF_OBJ="${TSM_BPF_OBJ:-$(dirname "$0")/tproxy.o}"
TPROXY_MARK="0xfee1dead"
ROUTING_TABLE="100"

# Auto-detect primary interface (first non-loopback with a default route)
if [ -z "${TSM_IFACE:-}" ]; then
    IFACE=$(ip route show default | awk '/default/ {print $5; exit}')
    if [ -z "$IFACE" ]; then
        echo "[tsm-tproxy] ERROR: could not auto-detect network interface." >&2
        echo "[tsm-tproxy]        Set TSM_IFACE to override." >&2
        exit 1
    fi
else
    IFACE="$TSM_IFACE"
fi

# ── Parse args ────────────────────────────────────────────────────────────────
TEARDOWN=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --iface)       IFACE="$2";       shift 2 ;;
        --proxy-port)  PROXY_PORT="$2";  shift 2 ;;
        --teardown)    TEARDOWN=1;       shift   ;;
        *) echo "[tsm-tproxy] unknown arg: $1" >&2; exit 1 ;;
    esac
done

# ── Teardown path ─────────────────────────────────────────────────────────────
if [ "$TEARDOWN" -eq 1 ]; then
    echo "[tsm-tproxy] Tearing down TPROXY rules on $IFACE..."

    tc filter del dev "$IFACE" egress 2>/dev/null || true
    tc qdisc del dev "$IFACE" clsact  2>/dev/null || true

    ip rule del fwmark "$TPROXY_MARK" lookup "$ROUTING_TABLE" 2>/dev/null || true
    ip route flush table "$ROUTING_TABLE" 2>/dev/null || true

    iptables -t nat    -D OUTPUT -m mark --mark "$TPROXY_MARK" \
        -p tcp -j REDIRECT --to-ports "$PROXY_PORT" 2>/dev/null || true
    iptables -t mangle -D OUTPUT -p tcp --dport 443 \
        -m mark ! --mark "$TPROXY_MARK" -j RETURN   2>/dev/null || true

    echo "[tsm-tproxy] Teardown complete."
    exit 0
fi

# ── Preflight checks ──────────────────────────────────────────────────────────
if [ "$(id -u)" -ne 0 ]; then
    echo "[tsm-tproxy] ERROR: must run as root (needs CAP_NET_ADMIN)." >&2
    exit 1
fi

if [ ! -f "$BPF_OBJ" ]; then
    echo "[tsm-tproxy] ERROR: BPF object not found: $BPF_OBJ" >&2
    echo "[tsm-tproxy]        Build with: make -C $(dirname "$0")/.." >&2
    exit 1
fi

echo "[tsm-tproxy] Setting up AI API TPROXY interception"
echo "[tsm-tproxy]   Interface:  $IFACE"
echo "[tsm-tproxy]   Proxy port: $PROXY_PORT"
echo "[tsm-tproxy]   Mark:       $TPROXY_MARK"

# ── Step 1: Attach TC clsact qdisc + BPF program ─────────────────────────────
echo "[tsm-tproxy] Step 1: attaching TC egress BPF hook..."

# Remove stale qdisc if already present
tc qdisc del dev "$IFACE" clsact 2>/dev/null || true

tc qdisc add dev "$IFACE" clsact
tc filter add dev "$IFACE" egress \
    bpf direct-action obj "$BPF_OBJ" sec tc_tproxy

echo "[tsm-tproxy]   TC hook attached to $IFACE egress."

# ── Step 2: Populate the ai_ips LPM trie via ebpf-loader ─────────────────────
# The Rust ebpf-loader is responsible for pinning maps and populating ai_ips.
# If it's already running, it will have loaded the CIDR list.  Emit a reminder.
echo "[tsm-tproxy] Step 2: AI CIDR population"
echo "[tsm-tproxy]   The ebpf-loader binary populates ai_ips at startup."
echo "[tsm-tproxy]   Default CIDRs loaded (OpenAI: 23.102.140.0/24, 13.107.238.0/24;"
echo "[tsm-tproxy]   Anthropic: 160.79.104.0/23; add more in /etc/tsm/ai-cidrs.conf)"

# ── Step 3: iptables OUTPUT nat REDIRECT ─────────────────────────────────────
echo "[tsm-tproxy] Step 3: installing iptables NAT redirect..."

# Exempt the TSM data plane's own egress from redirection (avoids loop).
# The data plane runs as a specific user or with SO_MARK = TPROXY_MARK cleared.
# We match on the mark being set by BPF (only AI-destined packets are marked).
iptables -t nat -C OUTPUT \
    -m mark --mark "$TPROXY_MARK" \
    -p tcp -j REDIRECT --to-ports "$PROXY_PORT" 2>/dev/null \
|| iptables -t nat -A OUTPUT \
    -m mark --mark "$TPROXY_MARK" \
    -p tcp -j REDIRECT --to-ports "$PROXY_PORT"

echo "[tsm-tproxy]   iptables NAT rule installed."

# ── Step 4: Policy routing for REDIRECT return path ──────────────────────────
echo "[tsm-tproxy] Step 4: policy routing..."

ip rule add fwmark "$TPROXY_MARK" lookup "$ROUTING_TABLE" 2>/dev/null \
|| echo "[tsm-tproxy]   ip rule already exists, skipping."

ip route add local default dev lo table "$ROUTING_TABLE" 2>/dev/null \
|| echo "[tsm-tproxy]   local route in table $ROUTING_TABLE already exists, skipping."

echo "[tsm-tproxy]   Policy routing configured (table $ROUTING_TABLE)."

# ── Step 5: Verify ───────────────────────────────────────────────────────────
echo "[tsm-tproxy] Verification:"
echo "  tc filters on $IFACE egress:"
tc filter show dev "$IFACE" egress 2>/dev/null | grep -E "bpf|handle" | head -5

echo "  iptables nat OUTPUT:"
iptables -t nat -L OUTPUT -n --line-numbers 2>/dev/null \
    | grep -E "REDIRECT|TPROXY|$PROXY_PORT" | head -5

echo ""
echo "[tsm-tproxy] Setup complete."
echo "[tsm-tproxy] All outbound TCP:443 to known AI APIs will be intercepted."
echo "[tsm-tproxy] TSM data plane must be listening on 0.0.0.0:$PROXY_PORT with SO_ORIGINAL_DST support."
echo "[tsm-tproxy] To remove: $0 --teardown"
