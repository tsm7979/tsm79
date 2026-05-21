/* xdp_ai_filter.c — XDP packet classifier for AI provider traffic.
 *
 * Companion to xdp_ddos.c.  Where xdp_ddos.c drops attack traffic,
 * this program CLASSIFIES and MARKS legitimate AI traffic for the
 * Rust dataplane to intercept, and REDIRECTS traffic destined for
 * locally-routed sessions to the vLLM/Ollama interface.
 *
 * Pipeline:
 *   1. Parse Ethernet → IPv4/IPv6 → TCP
 *   2. LPM trie: is dst IP in an AI provider CIDR?  If not → XDP_PASS
 *   3. Look up session cookie / src IP in session map
 *      → session_action == ROUTE_LOCAL: XDP redirect to lo:8080 (local model)
 *      → session_action == ROUTE_CLOUD: XDP_PASS (to Rust TPROXY)
 *   4. Write classifier result into per-CPU scratch map for Rust to read
 *
 * Maps:
 *   ai_ips           — LPM_TRIE: dst CIDR → ip_action
 *   tsm_session_xdp  — HASH: src_ip+sport+dst_ip+dport → route_action
 *   tsm_stats        — PERCPU_ARRAY: counters
 *   tsm_redirect_map — DEVMAP: redirect target interface index
 *
 * Compile:
 *   clang -target bpf -O2 -g -Wall \
 *         -I/usr/include/$(uname -m)-linux-gnu \
 *         -c xdp_ai_filter.c -o xdp_ai_filter.o
 *
 * Attach:
 *   ip link set dev eth0 xdp obj xdp_ai_filter.o sec xdp_classify
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "maps.h"

/* ── Stat indices ────────────────────────────────────────────────────────── */
#define STAT_XDP_AI_CLASSIFIED  10
#define STAT_XDP_AI_LOCAL       11
#define STAT_XDP_AI_CLOUD       12
#define STAT_XDP_NON_AI         13
#define STAT_XDP_REDIRECT_ERR   14

/* ── Route actions ───────────────────────────────────────────────────────── */
#define ROUTE_UNKNOWN           0
#define ROUTE_LOCAL             1   /* → local Ollama/vLLM */
#define ROUTE_CLOUD             2   /* → cloud AI provider (via TPROXY) */
#define ROUTE_BLOCK             3   /* → blocked (should have been dropped) */

/* ── Session key ─────────────────────────────────────────────────────────── */

struct session_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
};

struct session_entry {
    __u8  route_action;   /* ROUTE_* above */
    __u8  sensitive;      /* 1 if conversation contains sensitive data */
    __u16 _pad;
    __u64 pinned_at_ns;   /* when this session was pinned */
    __u64 last_seen_ns;   /* for TTL eviction by userspace sweeper */
};

/* ── Classifier result (written to scratch map for TPROXY context) ────────── */

struct classify_result {
    __u8  is_ai_traffic;
    __u8  route_action;
    __u8  is_sensitive;
    __u8  _pad;
    __u32 dst_ip;
    __u16 dst_port;
    __u16 src_port;
};

/* ── Maps ─────────────────────────────────────────────────────────────────── */

struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(max_entries, 500000);
    __type(key,         struct session_key);
    __type(value,       struct session_entry);
} tsm_session_xdp SEC(".maps");

struct {
    __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key,         __u32);
    __type(value,       struct classify_result);
} tsm_classify_scratch SEC(".maps");

struct {
    __uint(type,        BPF_MAP_TYPE_DEVMAP);
    __uint(max_entries, 256);
    __type(key,         __u32);   /* interface index */
    __type(value,       __u32);   /* target ifindex */
} tsm_redirect_map SEC(".maps");

/* ── Helpers ─────────────────────────────────────────────────────────────── */

static __always_inline void inc_stat(__u32 idx)
{
    __u64 *val = bpf_map_lookup_elem(&tsm_stats, &idx);
    if (val) __sync_fetch_and_add(val, 1);
}

#define BOUNDS_CHECK(ptr, end, size) \
    if ((void *)((char *)(ptr) + (size)) > (end)) return XDP_PASS

/* ── Write classifier result to per-CPU scratch ──────────────────────────── */

static __always_inline void write_scratch(
    __u8 is_ai, __u8 route, __u8 sensitive,
    __u32 dst_ip, __u16 dst_port, __u16 src_port)
{
    __u32 key = 0;
    struct classify_result *r = bpf_map_lookup_elem(&tsm_classify_scratch, &key);
    if (!r) return;
    r->is_ai_traffic = is_ai;
    r->route_action  = route;
    r->is_sensitive  = sensitive;
    r->dst_ip        = dst_ip;
    r->dst_port      = dst_port;
    r->src_port      = src_port;
}

/* ── XDP classifier ──────────────────────────────────────────────────────── */

SEC("xdp_classify")
int tsm_xdp_classify(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    __u64 now_ns   = bpf_ktime_get_ns();

    /* Parse Ethernet */
    struct ethhdr *eth = data;
    BOUNDS_CHECK(eth, data_end, sizeof(*eth));
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) return XDP_PASS;

    /* Parse IPv4 */
    struct iphdr *ip = (void *)(eth + 1);
    BOUNDS_CHECK(ip, data_end, sizeof(*ip));
    if (ip->protocol != IPPROTO_TCP) return XDP_PASS;

    __u32 dst_ip = ip->daddr;
    __u32 src_ip = ip->saddr;

    /* LPM trie: is this destined for an AI provider? */
    struct lpm_key lpm = { .prefixlen = 32, .addr = dst_ip };
    struct ip_action *action = bpf_map_lookup_elem(&ai_ips, &lpm);
    if (!action) {
        inc_stat(STAT_XDP_NON_AI);
        return XDP_PASS;  /* Not AI traffic */
    }

    /* Parse TCP for port and session lookup */
    __u32 ip_hlen = ip->ihl * 4;
    struct tcphdr *tcp = (void *)((char *)ip + ip_hlen);
    BOUNDS_CHECK(tcp, data_end, sizeof(*tcp));

    __u16 dst_port = bpf_ntohs(tcp->dest);
    __u16 src_port = bpf_ntohs(tcp->source);

    inc_stat(STAT_XDP_AI_CLASSIFIED);

    /* Look up existing session pin */
    struct session_key skey = {
        .src_ip   = src_ip,
        .dst_ip   = dst_ip,
        .src_port = src_port,
        .dst_port = dst_port,
    };
    struct session_entry *session = bpf_map_lookup_elem(&tsm_session_xdp, &skey);

    if (session) {
        session->last_seen_ns = now_ns;

        if (session->route_action == ROUTE_LOCAL) {
            /* Pinned to local model — redirect to loopback Ollama/vLLM */
            write_scratch(1, ROUTE_LOCAL, session->sensitive, dst_ip, dst_port, src_port);
            inc_stat(STAT_XDP_AI_LOCAL);

            /* Redirect to local model interface (ifindex 1 = lo by convention).
             * The userspace loader maps ifindex 1 → lo in tsm_redirect_map.
             * XDP_REDIRECT bypasses kernel routing entirely. */
            int ret = bpf_redirect_map(&tsm_redirect_map, 1, XDP_PASS);
            if (ret < 0) {
                inc_stat(STAT_XDP_REDIRECT_ERR);
                return XDP_PASS;
            }
            return XDP_REDIRECT;
        }
    }

    /* No session pin, or pinned to cloud → pass to Rust TPROXY */
    write_scratch(1, ROUTE_CLOUD, 0, dst_ip, dst_port, src_port);
    inc_stat(STAT_XDP_AI_CLOUD);

    /* Set socket mark so TC drop_bypass.c knows this is legitimate TSM traffic */
    /* Note: can't set skb->mark from XDP context; TC hook does this instead. */

    return XDP_PASS;
}

/* ── Session pin updater (called via BPF_PROG_RUN from Rust dataplane) ────── */

SEC("xdp_pin_session")
int tsm_pin_session(struct xdp_md *ctx)
{
    /* This section is a target for tail calls from the dataplane.
     * The Rust process calls BPF_MAP_UPDATE_ELEM directly on tsm_session_xdp
     * after the policy engine decides to pin a session.
     * This function is a placeholder for future in-kernel session management. */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
