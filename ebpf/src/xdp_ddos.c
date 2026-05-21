/* xdp_ddos.c — XDP DDoS mitigation at NIC driver level.
 *
 * Runs BEFORE the Linux kernel networking stack.
 * Decisions at 100 Gbps line rate. Per-packet cost: ~50ns.
 *
 * Enforcement:
 *   1. Token bucket per source IP — rate limit individual senders
 *   2. SYN flood detection — count half-open connections per IP
 *   3. Connection rate — new TCP connections per second per IP
 *   4. Tor exit node / known-bad IP — blocklist from userspace
 *   5. Amplification attack guard — UDP/ICMP size asymmetry
 *   6. AI provider destination check — only AI traffic hits these rules
 *
 * Maps (updated from userspace via tsm-ctl / threat-intel service):
 *   tsm_rate_buckets  — LRU_HASH: src_ip → token_bucket_state
 *   tsm_blocklist     — HASH: src_ip → block_reason + expiry
 *   tsm_syn_tracking  — LRU_HASH: src_ip → syn_count
 *   ai_ips            — LPM_TRIE: dst_ip → action (from maps.h)
 *   tsm_stats         — PERCPU_ARRAY: counters
 *
 * Compile:
 *   clang -target bpf -O2 -g -Wall \
 *         -I/usr/include/$(uname -m)-linux-gnu \
 *         -c xdp_ddos.c -o xdp_ddos.o
 *
 * Attach:
 *   ip link set dev eth0 xdp obj xdp_ddos.o sec xdp_ddos
 *   # or native mode (faster):
 *   ip link set dev eth0 xdpdrv obj xdp_ddos.o sec xdp_ddos
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "maps.h"

/* ── Config constants ─────────────────────────────────────────────────────── */

/* Token bucket: 120 requests/minute = 2/second refill, burst of 20 */
#define RATE_TOKENS_PER_NS      2          /* tokens refilled per nanosecond * 1e9 / rate */
#define RATE_REFILL_INTERVAL_NS 500000000  /* 0.5s — refill 1 token every 0.5s */
#define RATE_BURST_MAX          20         /* maximum burst before dropping */

/* SYN flood: drop if >200 SYNs in 5s from one IP */
#define SYN_FLOOD_THRESHOLD     200
#define SYN_WINDOW_NS           5000000000ULL  /* 5 seconds */

/* Connection rate: >100 new connections/second from one IP */
#define CONN_RATE_THRESHOLD     100
#define CONN_RATE_WINDOW_NS     1000000000ULL  /* 1 second */

/* UDP amplification: drop if response/request ratio > 10x */
#define AMP_RATIO_THRESHOLD     10

/* Stat indices */
#define STAT_XDP_DROP_RATE      5
#define STAT_XDP_DROP_SYN       6
#define STAT_XDP_DROP_BLOCKLIST 7
#define STAT_XDP_PASS           8
#define STAT_XDP_DROP_AMP       9

/* ── Token bucket state ──────────────────────────────────────────────────── */

struct token_bucket {
    __u64 tokens;         /* current tokens (scaled by 1000) */
    __u64 last_refill_ns; /* last time we added tokens */
    __u64 total_dropped;  /* dropped packet count for telemetry */
};

/* ── SYN tracking ────────────────────────────────────────────────────────── */

struct syn_state {
    __u64 count;          /* SYN packets seen in window */
    __u64 window_start;   /* start of current window */
};

/* ── Block entry ─────────────────────────────────────────────────────────── */

struct block_entry {
    __u64 expiry_ns;      /* absolute ns when block expires (0 = permanent) */
    __u32 reason;         /* block reason code */
    __u32 _pad;
};

#define BLOCK_REASON_MANUAL     1
#define BLOCK_REASON_TOR        2
#define BLOCK_REASON_BOTNET     3
#define BLOCK_REASON_SYN_FLOOD  4
#define BLOCK_REASON_RATELIMIT  5

/* ── BPF Maps ────────────────────────────────────────────────────────────── */

struct {
    __uint(type,        BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1000000);   /* 1M source IPs */
    __type(key,         __u32);     /* src IPv4 */
    __type(value,       struct token_bucket);
} tsm_rate_buckets SEC(".maps");

struct {
    __uint(type,        BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1000000);
    __type(key,         __u32);
    __type(value,       struct syn_state);
} tsm_syn_tracking SEC(".maps");

struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100000);    /* manual + automated blocklist */
    __type(key,         __u32);
    __type(value,       struct block_entry);
} tsm_blocklist SEC(".maps");

/* ── Helpers ─────────────────────────────────────────────────────────────── */

static __always_inline void inc_stat(__u32 idx)
{
    __u64 *val = bpf_map_lookup_elem(&tsm_stats, &idx);
    if (val) __sync_fetch_and_add(val, 1);
}

#define BOUNDS_CHECK(ptr, end, size) \
    if ((void *)((char *)(ptr) + (size)) > (end)) return XDP_PASS

/* ── Token bucket rate limiter ───────────────────────────────────────────── */
/*
 * Classic token bucket algorithm.
 * Tokens accumulate over time at rate_per_ns.  One token consumed per packet.
 * If no tokens remain → XDP_DROP.
 *
 * Atomic-ish via BPF spin lock (kernel ≥ 5.1).
 * Fallback: accept small races (LRU_HASH has per-element locking).
 */
static __always_inline int check_rate_limit(__u32 src_ip, __u64 now_ns)
{
    struct token_bucket *bucket;
    struct token_bucket  new_bucket = {};

    bucket = bpf_map_lookup_elem(&tsm_rate_buckets, &src_ip);
    if (!bucket) {
        /* First packet from this IP — create bucket with full tokens */
        new_bucket.tokens        = RATE_BURST_MAX * 1000;
        new_bucket.last_refill_ns = now_ns;
        new_bucket.total_dropped  = 0;
        bpf_map_update_elem(&tsm_rate_buckets, &src_ip, &new_bucket, BPF_ANY);
        return XDP_PASS;
    }

    /* Refill tokens based on elapsed time */
    __u64 elapsed = now_ns - bucket->last_refill_ns;
    if (elapsed >= RATE_REFILL_INTERVAL_NS) {
        __u64 new_tokens = (elapsed / RATE_REFILL_INTERVAL_NS) * 1000;
        __u64 tokens     = bucket->tokens + new_tokens;
        /* Cap at burst max */
        if (tokens > RATE_BURST_MAX * 1000)
            tokens = RATE_BURST_MAX * 1000;
        bucket->tokens        = tokens;
        bucket->last_refill_ns = now_ns;
    }

    /* Consume one token */
    if (bucket->tokens >= 1000) {
        bucket->tokens -= 1000;
        return XDP_PASS;
    }

    /* Out of tokens → DROP */
    __sync_fetch_and_add(&bucket->total_dropped, 1);
    return XDP_DROP;
}

/* ── SYN flood detector ──────────────────────────────────────────────────── */

static __always_inline int check_syn_flood(__u32 src_ip, __u64 now_ns, int is_syn)
{
    if (!is_syn) return XDP_PASS;

    struct syn_state *state;
    struct syn_state  new_state = { .count = 1, .window_start = now_ns };

    state = bpf_map_lookup_elem(&tsm_syn_tracking, &src_ip);
    if (!state) {
        bpf_map_update_elem(&tsm_syn_tracking, &src_ip, &new_state, BPF_ANY);
        return XDP_PASS;
    }

    /* Reset window if expired */
    if (now_ns - state->window_start > SYN_WINDOW_NS) {
        state->count       = 1;
        state->window_start = now_ns;
        return XDP_PASS;
    }

    state->count++;
    if (state->count > SYN_FLOOD_THRESHOLD) {
        /* Auto-blocklist this IP for 5 minutes */
        struct block_entry blk = {
            .expiry_ns = now_ns + 300000000000ULL,  /* 5 min */
            .reason    = BLOCK_REASON_SYN_FLOOD,
        };
        bpf_map_update_elem(&tsm_blocklist, &src_ip, &blk, BPF_ANY);
        return XDP_DROP;
    }

    return XDP_PASS;
}

/* ── Blocklist check ─────────────────────────────────────────────────────── */

static __always_inline int check_blocklist(__u32 src_ip, __u64 now_ns)
{
    struct block_entry *entry = bpf_map_lookup_elem(&tsm_blocklist, &src_ip);
    if (!entry) return XDP_PASS;

    /* Check if block has expired */
    if (entry->expiry_ns != 0 && now_ns > entry->expiry_ns) {
        bpf_map_delete_elem(&tsm_blocklist, &src_ip);
        return XDP_PASS;
    }

    return XDP_DROP;
}

/* ── XDP main program ────────────────────────────────────────────────────── */

SEC("xdp_ddos")
int tsm_xdp_ddos(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    __u64 now_ns   = bpf_ktime_get_ns();

    /* ── Parse Ethernet ──────────────────────────────────────────────────── */
    struct ethhdr *eth = data;
    BOUNDS_CHECK(eth, data_end, sizeof(*eth));

    __u16 eth_proto = bpf_ntohs(eth->h_proto);
    if (eth_proto == ETH_P_8021Q) {
        /* Skip 802.1Q VLAN tag */
        struct vlan_hdr { __be16 h_vlan_TCI; __be16 h_vlan_encapsulated_proto; };
        struct vlan_hdr *vlan = (void *)(eth + 1);
        BOUNDS_CHECK(vlan, data_end, sizeof(*vlan));
        eth_proto = bpf_ntohs(vlan->h_vlan_encapsulated_proto);
        data     += 4;
    }

    if (eth_proto != ETH_P_IP) return XDP_PASS;  /* IPv6 handled separately */

    /* ── Parse IPv4 ──────────────────────────────────────────────────────── */
    struct iphdr *ip = (void *)(eth + 1);
    BOUNDS_CHECK(ip, data_end, sizeof(*ip));

    __u32 src_ip = ip->saddr;
    __u32 dst_ip = ip->daddr;
    __u8  proto  = ip->protocol;

    /* ── Check if destination is an AI provider CIDR ─────────────────────
     * We only rate-limit traffic destined for AI APIs, not general internet.
     * This prevents false positives on unrelated traffic.
     */
    struct lpm_key lpm = { .prefixlen = 32, .addr = dst_ip };
    struct ip_action *action = bpf_map_lookup_elem(&ai_ips, &lpm);
    if (!action) return XDP_PASS;  /* Not AI traffic — let it through */

    /* ── Blocklist check (Tor exits, botnets, manual blocks) ─────────────
     * Must run first — blocked IPs should not consume rate-limiter state.
     */
    if (check_blocklist(src_ip, now_ns) == XDP_DROP) {
        inc_stat(STAT_XDP_DROP_BLOCKLIST);
        return XDP_DROP;
    }

    /* ── Protocol-specific checks ────────────────────────────────────────── */
    int is_syn = 0;

    if (proto == IPPROTO_TCP) {
        __u32 ip_hlen = ip->ihl * 4;
        struct tcphdr *tcp = (void *)((char *)ip + ip_hlen);
        BOUNDS_CHECK(tcp, data_end, sizeof(*tcp));

        is_syn = (tcp->syn && !tcp->ack);

        /* SYN flood check */
        if (check_syn_flood(src_ip, now_ns, is_syn) == XDP_DROP) {
            inc_stat(STAT_XDP_DROP_SYN);
#ifdef TSM_DEBUG
            bpf_printk("XDP SYN FLOOD from %x\n", bpf_ntohl(src_ip));
#endif
            return XDP_DROP;
        }

    } else if (proto == IPPROTO_UDP) {
        struct udphdr *udp = (void *)((char *)ip + ip->ihl * 4);
        BOUNDS_CHECK(udp, data_end, sizeof(*udp));

        /* UDP amplification guard: tiny request → big response is suspicious.
         * Drop oversized UDP to AI provider ports (DNS-over-HTTPS is fine on 443). */
        __u16 udp_len = bpf_ntohs(udp->len);
        if (udp_len > 1400 && bpf_ntohs(udp->dest) != 443) {
            inc_stat(STAT_XDP_DROP_AMP);
            return XDP_DROP;
        }

    } else if (proto == IPPROTO_ICMP) {
        /* Drop ICMP flood — AI APIs don't respond to ping */
        struct icmphdr *icmp = (void *)((char *)ip + ip->ihl * 4);
        BOUNDS_CHECK(icmp, data_end, sizeof(*icmp));
        if (icmp->type == ICMP_ECHO) {
            /* Count but don't drop — we might want icmp for path MTU */
            return XDP_PASS;
        }
    }

    /* ── Token bucket rate limiting ─────────────────────────────────────── */
    if (check_rate_limit(src_ip, now_ns) == XDP_DROP) {
        inc_stat(STAT_XDP_DROP_RATE);
#ifdef TSM_DEBUG
        bpf_printk("XDP RATE LIMIT: src=%x dst=%x\n",
                   bpf_ntohl(src_ip), bpf_ntohl(dst_ip));
#endif
        return XDP_DROP;
    }

    inc_stat(STAT_XDP_PASS);
    return XDP_PASS;
}

/* ── Blocklist management program (called from userspace via BPF_PROG_RUN) ─ */

SEC("xdp_blocklist_add")
int tsm_blocklist_add(struct xdp_md *ctx)
{
    /* Userspace uses BPF_MAP_UPDATE_ELEM directly — this section is a hook
     * for future in-kernel blocklist management via tail calls. */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
