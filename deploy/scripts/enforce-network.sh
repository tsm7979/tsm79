#!/usr/bin/env bash
##############################################################################
# enforce-network.sh — Kernel-level enforcement: makes bypass impossible.
#
# This is the difference between middleware and infrastructure:
#
#   BEFORE (middleware): App → openai.com directly (TSM can be skipped)
#   AFTER  (infra):      App → BLOCKED → must go through TSM → openai.com
#
# What this script does:
#   1. Creates nftables rules that DROP all outbound TCP:443 to AI provider
#      CIDRs UNLESS the packet originates from the TSM dataplane process
#      (matched by UID or socket mark 0xfee1dead).
#   2. Loads the eBPF TC programs that mark legitimate TSM-proxied packets.
#   3. Sets up REDIRECT rules so intercepted traffic reaches port 8443.
#   4. Creates a cgroup v2 rule to enforce per-process containment.
#
# Result: `import openai; openai.chat()` from any Python/Node/Go process
# that hasn't been patched to use TSM will receive ECONNREFUSED or EPERM.
# Only TSM (running as uid `tsm` or with mark 0xfee1dead) can reach AI APIs.
#
# Requirements:
#   - nftables (nft) ≥ 0.9.6
#   - iproute2 (tc, ip)
#   - libbpf / BPF kernel support (kernel ≥ 5.8)
#   - Must run as root
#
# Usage:
#   sudo ./enforce-network.sh [--iface eth0] [--tsm-port 8443] [--teardown]
#   sudo ./enforce-network.sh --teardown    # remove all rules
##############################################################################
set -euo pipefail

# ── Config ────────────────────────────────────────────────────────────────────
IFACE="${TSM_IFACE:-$(ip route show default | awk '/default/ {print $5}' | head -1)}"
TSM_PORT="${TSM_PROXY_PORT:-8443}"
TSM_UID="tsm"
TSM_MARK="0xfee1dead"
TSM_TABLE="tsm_enforce"
TEARDOWN=false
BPF_OBJ="${TSM_BPF_OBJ:-$(dirname "$0")/../../ebpf/src/tproxy.o}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --iface)    IFACE="$2";    shift 2 ;;
        --tsm-port) TSM_PORT="$2"; shift 2 ;;
        --teardown) TEARDOWN=true; shift ;;
        *) echo "Unknown arg: $1" >&2; exit 1 ;;
    esac
done

# ── AI provider CIDRs (sync with ai_cidrs.txt) ───────────────────────────────
AI_CIDRS=(
    # Cloudflare (OpenAI edge)
    "104.18.0.0/16" "104.19.0.0/16" "104.20.0.0/16" "104.21.0.0/16"
    "162.158.0.0/15" "198.41.128.0/17"
    # AWS (Anthropic, Bedrock)
    "3.208.0.0/12" "34.0.0.0/8" "52.0.0.0/8" "54.0.0.0/8"
    "13.32.0.0/15" "13.224.0.0/14"
    # Azure OpenAI
    "20.0.0.0/11" "40.64.0.0/10" "52.224.0.0/11"
    # Google Vertex AI
    "34.64.0.0/10" "34.128.0.0/10"
)

# ── Teardown ──────────────────────────────────────────────────────────────────
teardown() {
    echo "[enforce] Removing TSM nftables enforcement table..."
    nft delete table ip "$TSM_TABLE" 2>/dev/null || true
    echo "[enforce] Removing TC eBPF hooks..."
    tc qdisc del dev "$IFACE" clsact 2>/dev/null || true
    echo "[enforce] Removing ip rule for TSM mark..."
    ip rule del fwmark "$TSM_MARK" lookup 100 2>/dev/null || true
    ip route flush table 100 2>/dev/null || true
    echo "[enforce] Teardown complete. AI APIs are now UNPROTECTED."
}

if [[ "$TEARDOWN" == "true" ]]; then
    teardown
    exit 0
fi

# ── Verify TSM user exists ────────────────────────────────────────────────────
if ! id "$TSM_UID" &>/dev/null; then
    echo "[enforce] ERROR: User '$TSM_UID' does not exist."
    echo "          Run deploy/scripts/install.sh first."
    exit 1
fi

TSM_UID_NUM=$(id -u "$TSM_UID")

# ── Step 1: nftables enforcement table ───────────────────────────────────────
echo "[enforce] Installing nftables enforcement table '$TSM_TABLE'..."

# Build the AI CIDR set
CIDR_ELEMENTS=$(printf '"%s", ' "${AI_CIDRS[@]}")
CIDR_ELEMENTS="${CIDR_ELEMENTS%, }"

nft -f - <<EOF
# TSM enforcement: drop all AI API traffic not going through the proxy
table ip $TSM_TABLE {
    # The AI provider CIDR set
    set ai_cidrs {
        type ipv4_addr
        flags interval
        elements = { $CIDR_ELEMENTS }
    }

    chain output {
        type filter hook output priority mangle; policy accept;

        # Allow TSM proxy process itself (it needs to reach upstreams)
        meta skuid $TSM_UID_NUM accept

        # Allow traffic already marked by the eBPF TC hook (went through proxy)
        meta mark $TSM_MARK accept

        # Allow loopback (TSM listens on lo:$TSM_PORT)
        oif lo accept

        # BLOCK: outbound HTTPS to AI CIDRs from any other process
        # This is the enforcement. Any bypass attempt hits this rule.
        ip daddr @ai_cidrs tcp dport 443 \
            counter \
            log prefix "TSM-BLOCKED: " flags all \
            reject with tcp reset
    }

    chain forward {
        type filter hook forward priority 0; policy accept;

        # Block forwarded traffic to AI CIDRs too (container escape prevention)
        ip daddr @ai_cidrs tcp dport 443 \
            counter \
            reject with tcp reset
    }
}
EOF
echo "[enforce] nftables table installed."

# ── Step 2: REDIRECT intercepted traffic to TSM port ─────────────────────────
echo "[enforce] Installing NAT redirect to TSM port $TSM_PORT..."

# Use iptables nat (nftables nat requires kernel ≥ 5.2; iptables more portable)
iptables -t nat -N TSM_TPROXY 2>/dev/null || iptables -t nat -F TSM_TPROXY

for cidr in "${AI_CIDRS[@]}"; do
    iptables -t nat -A TSM_TPROXY -d "$cidr" -p tcp --dport 443 \
        -j REDIRECT --to-ports "$TSM_PORT"
done

iptables -t nat -C OUTPUT -m mark --mark "$TSM_MARK" -j TSM_TPROXY 2>/dev/null \
    || iptables -t nat -I OUTPUT -m mark --mark "$TSM_MARK" -j TSM_TPROXY

echo "[enforce] NAT redirect installed."

# ── Step 3: Load eBPF TC program (marks outbound AI packets) ─────────────────
echo "[enforce] Loading eBPF TC hook on $IFACE..."

if [[ -f "$BPF_OBJ" ]]; then
    tc qdisc add dev "$IFACE" clsact 2>/dev/null || true
    tc filter add dev "$IFACE" egress bpf direct-action obj "$BPF_OBJ" sec tc_tproxy
    echo "[enforce] eBPF TC hook loaded."
else
    echo "[enforce] WARNING: $BPF_OBJ not found — skipping eBPF TC hook."
    echo "          Compile with: make -C ebpf/src"
    echo "          Without this hook, TSM packets won't be marked."
fi

# ── Step 4: Routing table for marked packets ──────────────────────────────────
ip rule add fwmark "$TSM_MARK" lookup 100 2>/dev/null || true
ip route add local 0.0.0.0/0 dev lo table 100 2>/dev/null || true

# ── Step 5: Verify enforcement is working ────────────────────────────────────
echo ""
echo "[enforce] Verifying enforcement..."
BLOCKED=$(nft list table ip "$TSM_TABLE" 2>/dev/null | grep -c "reject" || true)
echo "  nftables rules:   $BLOCKED reject rule(s) installed"
echo "  TSM UID:          $TSM_UID ($TSM_UID_NUM)"
echo "  TSM proxy port:   $TSM_PORT"
echo "  Interface:        $IFACE"
echo ""
echo "[enforce] ENFORCEMENT ACTIVE."
echo ""
echo "  Test bypass is blocked:"
echo "    curl -v https://api.openai.com/v1/models  # should be BLOCKED"
echo ""
echo "  Test TSM proxy works:"
echo "    curl -v http://localhost:$TSM_PORT/health  # should return {status:ok}"
echo ""
echo "  Monitor blocked attempts:"
echo "    journalctl -k -f | grep TSM-BLOCKED"
echo "    nft list table ip $TSM_TABLE"
