/* drop_bypass.c — TSM enforcement: DROP unauthorized AI API traffic.
 *
 * Companion to tproxy.c. Where tproxy.c MARKS legitimate TSM-proxied packets,
 * this TC ingress/egress program DROPS packets that:
 *   - Are destined for a known AI provider CIDR on port 443
 *   - Do NOT carry the TSM socket mark (0xfee1dead)
 *   - Are NOT sourced from the local TSM dataplane process
 *
 * This closes the enforcement gap: without this program, the nftables rules
 * catch application-layer bypasses, but packets already in-flight at the
 * TC layer with no mark would still pass.
 *
 * Attach point:
 *   tc filter add dev <iface> egress bpf direct-action obj drop_bypass.o sec tc_drop
 *
 * Maps shared with tproxy.c (via maps.h):
 *   ai_ips         — LPM trie of AI provider CIDRs
 *   tsm_stats      — per-CPU counters
 *
 * Compile:
 *   clang -target bpf -O2 -g -Wall \
 *         -Wno-unused-value -Wno-pointer-sign \
 *         -I/usr/include/$(uname -m)-linux-gnu \
 *         -c drop_bypass.c -o drop_bypass.o
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "maps.h"

#define TSM_MARK     0xfee1dead
#define AI_API_PORT  443

/* Stat indices */
#define STAT_DROP_BYPASS  3    /* new counter — must add to maps.h */
#define STAT_ALLOWED_MARK 4

#define CHECK_BOUNDS(ptr, end, size) \
    if ((void *)((__u8 *)(ptr) + (size)) > (end)) return TC_ACT_OK

static __always_inline void inc_stat(__u32 idx)
{
    __u64 *val = bpf_map_lookup_elem(&tsm_stats, &idx);
    if (val) __sync_fetch_and_add(val, 1);
}

/* ── TC egress enforcement ───────────────────────────────────────────────────
 * For every outbound packet:
 *   1. If not TCP:443 to an AI CIDR → pass (not our concern)
 *   2. If socket mark == TSM_MARK  → pass (going through TSM)
 *   3. Otherwise                   → DROP (bypass attempt)
 */
SEC("tc_drop")
int tsm_drop_bypass(struct __sk_buff *skb)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data     = (void *)(long)skb->data;

    /* ── Parse Ethernet ─────────────────────────────────────────────────── */
    struct ethhdr *eth = data;
    CHECK_BOUNDS(eth, data_end, sizeof(*eth));
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return TC_ACT_OK;

    /* ── Parse IPv4 ─────────────────────────────────────────────────────── */
    struct iphdr *ip = (void *)(eth + 1);
    CHECK_BOUNDS(ip, data_end, sizeof(*ip));
    if (ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    /* ── Parse TCP ──────────────────────────────────────────────────────── */
    __u32 ip_hlen = ip->ihl * 4;
    struct tcphdr *tcp = (void *)((void *)ip + ip_hlen);
    CHECK_BOUNDS(tcp, data_end, sizeof(*tcp));

    /* Only care about HTTPS (port 443) */
    if (bpf_ntohs(tcp->dest) != AI_API_PORT)
        return TC_ACT_OK;

    /* ── AI CIDR lookup ─────────────────────────────────────────────────── */
    struct lpm_key key = {
        .prefixlen = 32,
        .addr      = ip->daddr,
    };
    struct ip_action *action = bpf_map_lookup_elem(&ai_ips, &key);
    if (!action)
        return TC_ACT_OK;  /* Not an AI provider — pass */

    /* ── Enforcement decision ───────────────────────────────────────────── */
    if (skb->mark == TSM_MARK) {
        /* Legitimate: already processed by TSM TPROXY */
        inc_stat(STAT_ALLOWED_MARK);
        return TC_ACT_OK;
    }

    /* BYPASS ATTEMPT: drop it */
    inc_stat(STAT_DROP_BYPASS);

    /* Use bpf_trace_printk for debugging — remove in production */
#ifdef TSM_DEBUG
    bpf_printk("TSM DROP bypass: src=%x dst=%x port=443\n",
               bpf_ntohl(ip->saddr), bpf_ntohl(ip->daddr));
#endif

    return TC_ACT_SHOT;  /* DROP */
}

char _license[] SEC("license") = "GPL";
