/* TSMv2 — TC egress TPROXY marker.
 *
 * Attaches to the TC egress hook (clsact qdisc) on the primary network
 * interface.  For every outbound TCP:443 packet whose destination IP matches
 * a known AI provider CIDR in the ai_ips LPM trie, the program:
 *
 *   1. Sets skb->mark = TPROXY_MARK (0xfee1dead).
 *   2. Increments tsm_stats[STAT_TPROXY_MARKED].
 *
 * The mark is consumed by an ip-rule / iptables chain set up by
 * ebpf/setup-tproxy.sh, which redirects marked packets to the local TSM
 * data plane on port 8443 using iptables REDIRECT (OUTPUT nat chain).
 *
 * Transparency for the data plane:
 *   The Rust data plane binds port 8443 and recovers the original destination
 *   IP:port via getsockopt(SO_ORIGINAL_DST) before forwarding upstream.
 *
 * Why TC egress and not XDP?
 *   XDP only fires on ingress (RX path).  Outbound application traffic
 *   flows through the TC egress hook — after the kernel routing decision
 *   and socket send, before the NIC driver transmits the frame.
 *
 * Compile:
 *   clang -target bpf -O2 -Wall \
 *         -Wno-unused-value -Wno-pointer-sign \
 *         -Wno-compare-distinct-pointer-types \
 *         -I/usr/include/$(uname -m)-linux-gnu \
 *         -c tproxy.c -o tproxy.o
 *
 * Attach (done by setup-tproxy.sh):
 *   tc qdisc add dev <iface> clsact
 *   tc filter add dev <iface> egress bpf direct-action obj tproxy.o sec tc_tproxy
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

/* Socket mark that triggers TPROXY redirect via ip-rule + iptables */
#define TPROXY_MARK  0xfee1dead

/* Destination port to intercept (HTTPS / AI APIs) */
#define AI_API_PORT  443

/* ── Bounds check ─────────────────────────────────────────────────────────────*/
#define CHECK_BOUNDS(ptr, end, size) \
    if ((void *)((__u8 *)(ptr) + (size)) > (end)) return TC_ACT_OK

/* ── TC egress TPROXY marker ─────────────────────────────────────────────────*/

SEC("tc_tproxy")
int tsm_tc_tproxy(struct __sk_buff *skb)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    /* ── 1. Parse Ethernet ───────────────────────────────────────────────── */
    struct ethhdr *eth = data;
    CHECK_BOUNDS(eth, data_end, sizeof(*eth));

    /* Only handle IPv4; let IPv6 and other protocols pass unmolested */
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return TC_ACT_OK;

    /* ── 2. Parse IPv4 ───────────────────────────────────────────────────── */
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    CHECK_BOUNDS(ip, data_end, sizeof(*ip));

    /* Only intercept TCP */
    if (ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    __u32 dst_ip = ip->daddr;  /* network byte order */

    /* ── 3. Parse TCP — check destination port ───────────────────────────── */
    __u8 *l4 = (__u8 *)ip + (ip->ihl * 4);
    CHECK_BOUNDS(l4, data_end, sizeof(struct tcphdr));

    struct tcphdr *tcp = (struct tcphdr *)l4;
    __u16 dst_port = bpf_ntohs(tcp->dest);

    /* Only care about HTTPS (port 443) */
    if (dst_port != AI_API_PORT)
        return TC_ACT_OK;

    /* ── 4. LPM trie lookup — is dst_ip an AI provider address? ─────────── */
    struct ai_lpm_key key = {
        .prefixlen = 32,   /* exact /32 host lookup; kernel LPM finds best match */
        .ip        = dst_ip,
    };

    __u8 *reason = bpf_map_lookup_elem(&ai_ips, &key);
    if (!reason)
        return TC_ACT_OK;  /* not an AI provider — pass unchanged */

    /* ── 5. Mark packet for TPROXY redirect ──────────────────────────────── */
    skb->mark = TPROXY_MARK;

    /* ── 6. Update TPROXY-marked counter ─────────────────────────────────── */
    __u32 mark_key = STAT_TPROXY_MARKED;
    __u64 *marked  = bpf_map_lookup_elem(&tsm_stats, &mark_key);
    if (marked)
        __sync_fetch_and_add(marked, 1);

    /* ── 7. Log (debug builds only — bpf_trace_printk is rate-limited) ───── */
#ifdef TSM_DEBUG
    bpf_printk("tsm-tproxy: marking %pI4:%d → reason=%d\n",
               &dst_ip, dst_port, (int)*reason);
#endif

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
