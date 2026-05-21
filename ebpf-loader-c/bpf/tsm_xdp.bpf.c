// SPDX-License-Identifier: GPL-2.0
//
// tsm_xdp.bpf.c — TSM XDP packet filter for AI provider CIDR blocking.
//
// Loaded by tsm_loader (userspace) via libbpf.
// The loader populates the `tsm_ai_cidrs` LPM trie map with CIDRs to match.
// Matched packets are passed (XDP_PASS) so the kernel's AI proxy can handle
// them; unmatched packets are also passed (we are not a drop firewall here —
// the XDP program is used for fast tagging and rate-limit enforcement).
//
// Map layout:
//   tsm_ai_cidrs : LPM_TRIE  key=struct lpm_key{prefixlen,addr}
//                             value=struct cidr_value{action,pad[3]}
//   tsm_pkt_count: PERCPU_ARRAY  [0]=passed, [1]=ai_matched, [2]=dropped
//
// To compile:
//   clang -target bpf -O2 -g -I/usr/include/$(uname -m)-linux-gnu \
//         -c tsm_xdp.bpf.c -o tsm_xdp.bpf.o

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// ── LPM key matches tsm_loader.c struct lpm_key ───────────────────────────────
struct lpm_key {
    __u32 prefixlen;
    __u32 addr;        // network-byte-order IPv4
};

struct cidr_value {
    __u8  action;      // 0=pass, 1=mark (future: redirect, rate-limit)
    __u8  pad[3];
};

// ── Maps ──────────────────────────────────────────────────────────────────────
struct {
    __uint(type,        BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 4096);
    __uint(map_flags,   BPF_F_NO_PREALLOC);
    __type(key,         struct lpm_key);
    __type(value,       struct cidr_value);
} tsm_ai_cidrs SEC(".maps");

struct {
    __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 3);
    __type(key,         __u32);
    __type(value,       __u64);
} tsm_pkt_count SEC(".maps");

// ── Counter helper ─────────────────────────────────────────────────────────────
static __always_inline void inc_counter(__u32 idx)
{
    __u64 *val = bpf_map_lookup_elem(&tsm_pkt_count, &idx);
    if (val)
        __sync_fetch_and_add(val, 1);
}

// ── XDP entry point ───────────────────────────────────────────────────────────
SEC("xdp")
int tsm_xdp_filter(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    // ── Parse Ethernet header ─────────────────────────────────────────────────
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        goto pass;

    // Only handle IPv4
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        goto pass;

    // ── Parse IPv4 header ─────────────────────────────────────────────────────
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        goto pass;

    // Only TCP (AI proxy traffic)
    if (ip->protocol != IPPROTO_TCP)
        goto pass;

    // ── LPM trie lookup on destination IP ────────────────────────────────────
    struct lpm_key key = {
        .prefixlen = 32,
        .addr      = ip->daddr,     // already in network byte order
    };

    struct cidr_value *val = bpf_map_lookup_elem(&tsm_ai_cidrs, &key);
    if (val) {
        // Destination is a known AI provider CIDR — mark packet
        // (future: redirect to dataplane port, enforce per-IP rate limits)
        inc_counter(1);             // ai_matched
        // For now: pass (allow) — tagging is done; enforcement is in userspace
        goto pass;
    }

pass:
    inc_counter(0);                 // total passed
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
