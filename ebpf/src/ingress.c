/* TSMv2 — XDP ingress program.
 *
 * Runs at the NIC receive path (before the kernel network stack) via the
 * eXpress Data Path (XDP) hook.
 *
 * Actions taken per packet:
 *   1. Parse Ethernet → IP → TCP/UDP.  Non-IP traffic → XDP_PASS.
 *   2. If src_ip is in ip_blocked → XDP_DROP (DDoS mitigation at NIC speed).
 *   3. Increment ip_request_count[src_ip] atomically (per-CPU).
 *   4. Increment global tsm_stats[STAT_TOTAL_PACKETS].
 *   5. If dst_port matches the configured TSM port → XDP_PASS (userspace handles).
 *   6. All other traffic → XDP_PASS.
 *
 * Compile:
 *   clang -target bpf -O2 -Wall -Wno-unused-value -Wno-pointer-sign \
 *         -Wno-compare-distinct-pointer-types \
 *         -I/usr/include/$(uname -m)-linux-gnu \
 *         -c ingress.c -o ingress.o
 *
 * Load & attach via the Rust ebpf-loader binary.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "maps.h"

/* ── Bounds-check helpers ────────────────────────────────────────────────────
 *
 * The BPF verifier requires every pointer dereference to be bounds-checked.
 * We define a simple macro to validate that a pointer + size stays within the
 * packet data range provided by xdp_md.
 */
#define CHECK_BOUNDS(ptr, end, size) \
    if ((void *)((__u8 *)(ptr) + (size)) > (end)) return XDP_PASS

/* ── XDP program ─────────────────────────────────────────────────────────────*/

SEC("xdp")
int tsm_xdp_ingress(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* ── Step 1: Parse Ethernet header ──────────────────────────────────── */
    struct ethhdr *eth = data;
    CHECK_BOUNDS(eth, data_end, sizeof(*eth));

    __u16 eth_proto = bpf_ntohs(eth->h_proto);

    /* Handle 802.1Q VLAN tag */
    __u8 *payload = (__u8 *)(eth + 1);
    if (eth_proto == ETH_P_8021Q) {
        CHECK_BOUNDS(payload, data_end, 4);
        eth_proto = bpf_ntohs(*(__u16 *)(payload + 2));
        payload  += 4;
    }

    /* Only process IPv4 for now; pass IPv6 and everything else */
    if (eth_proto != ETH_P_IP)
        return XDP_PASS;

    /* ── Step 2: Parse IPv4 header ───────────────────────────────────────── */
    struct iphdr *ip = (struct iphdr *)payload;
    CHECK_BOUNDS(ip, data_end, sizeof(*ip));

    __u32 src_ip  = ip->saddr;   /* network byte order */
    __u8  ip_proto = ip->protocol;

    /* Advance past variable-length IPv4 header */
    __u8 *l4 = payload + (ip->ihl * 4);
    CHECK_BOUNDS(l4, data_end, 2); /* need at least dst port */

    /* ── Step 3: Extract destination port ────────────────────────────────── */
    __u16 dst_port_net = 0;
    if (ip_proto == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)l4;
        CHECK_BOUNDS(tcp, data_end, sizeof(*tcp));
        dst_port_net = tcp->dest;
    } else if (ip_proto == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)l4;
        CHECK_BOUNDS(udp, data_end, sizeof(*udp));
        dst_port_net = udp->dest;
    }
    /* Non TCP/UDP: still count + block check, then pass */

    /* ── Step 4: Update global total counter ─────────────────────────────── */
    __u32 stat_key = STAT_TOTAL_PACKETS;
    __u64 *total   = bpf_map_lookup_elem(&tsm_stats, &stat_key);
    if (total)
        __sync_fetch_and_add(total, 1);

    /* ── Step 5: Check blocked IP set ────────────────────────────────────── */
    __u8 *blocked = bpf_map_lookup_elem(&ip_blocked, &src_ip);
    if (blocked && *blocked == 1) {
        /* Increment dropped counter */
        __u32 drop_key  = STAT_DROPPED_PACKETS;
        __u64 *dropped  = bpf_map_lookup_elem(&tsm_stats, &drop_key);
        if (dropped)
            __sync_fetch_and_add(dropped, 1);
        return XDP_DROP;
    }

    /* ── Step 6: Increment per-IP packet counter (per-CPU) ───────────────── */
    __u64 *ip_cnt = bpf_map_lookup_elem(&ip_request_count, &src_ip);
    if (ip_cnt) {
        /* Existing entry — increment in-place (lock-free on per-CPU map) */
        *ip_cnt += 1;
    } else {
        /* New IP — insert with count = 1 */
        __u64 init = 1;
        bpf_map_update_elem(&ip_request_count, &src_ip, &init, BPF_NOEXIST);
    }

    /* ── Step 7: Check if this is TSM traffic (dst port match) ───────────── */
    __u32 cfg_key = 0;
    __u16 *tsm_port_p = bpf_map_lookup_elem(&tsm_config, &cfg_key);
    __u16 tsm_port    = tsm_port_p ? *tsm_port_p : 8080;

    if (dst_port_net != 0 && bpf_ntohs(dst_port_net) == tsm_port) {
        /* TSM traffic — increment passed counter */
        __u32 pass_key = STAT_PASSED_PACKETS;
        __u64 *passed  = bpf_map_lookup_elem(&tsm_stats, &pass_key);
        if (passed)
            __sync_fetch_and_add(passed, 1);
    }

    /* Pass all non-blocked traffic to the kernel network stack */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
