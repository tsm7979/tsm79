/* TSMv2 — TC egress program (optional response tagging).
 *
 * Attaches to the TC egress hook (not XDP — XDP only sees ingress).
 * Tags outbound packets from the TSM data plane with a DSCP mark so that
 * upstream network equipment can identify TSM-processed traffic.
 *
 * DSCP value used: CS3 (0x18 = 0b011000 << 2 = 0x60 in the ToS byte).
 * This is a best-effort advisory mark and does not affect routing.
 *
 * Compile (part of the ebpf/Makefile):
 *   clang -target bpf -O2 -Wall \
 *         -I/usr/include/$(uname -m)-linux-gnu \
 *         -c egress.c -o egress.o
 *
 * Attach via `tc`:
 *   tc qdisc add dev <iface> clsact
 *   tc filter add dev <iface> egress bpf direct-action obj egress.o sec tc_egress
 *
 * Or via the Rust ebpf-loader (optional — the loader skips egress if not root
 * or if the interface doesn't support TC clsact).
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "maps.h"

/* DSCP CS3 in the IPv4 TOS field: bits [7:2] = 0b011000, bits [1:0] = 0 */
#define TSM_DSCP_MARK  0x60

/* TSM source port (set at compile time; loader updates tsm_config map) */
#define TSM_SRC_PORT   8080

/* ── Bounds-check helper ─────────────────────────────────────────────────────*/
#define CHECK_BOUNDS(ptr, end, size) \
    if ((void *)((__u8 *)(ptr) + (size)) > (end)) return TC_ACT_OK

/* ── TC egress program ───────────────────────────────────────────────────────*/

SEC("tc_egress")
int tsm_tc_egress(struct __sk_buff *skb)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    /* ── Parse Ethernet ──────────────────────────────────────────────────── */
    struct ethhdr *eth = data;
    CHECK_BOUNDS(eth, data_end, sizeof(*eth));

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return TC_ACT_OK;

    /* ── Parse IPv4 ──────────────────────────────────────────────────────── */
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    CHECK_BOUNDS(ip, data_end, sizeof(*ip));

    if (ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    /* ── Parse TCP ───────────────────────────────────────────────────────── */
    __u8 *l4 = (__u8 *)ip + (ip->ihl * 4);
    /* Need at least 2 bytes for src port */
    if ((void *)(l4 + 2) > data_end)
        return TC_ACT_OK;

    __u16 src_port = bpf_ntohs(*(__u16 *)l4);

    /* ── Check if this is traffic from the TSM data plane ────────────────── */
    __u32 cfg_key   = 0;
    __u16 *tsm_port = bpf_map_lookup_elem(&tsm_config, &cfg_key);
    __u16  port     = tsm_port ? *tsm_port : TSM_SRC_PORT;

    if (src_port != port)
        return TC_ACT_OK;

    /* ── Tag: set DSCP CS3 in the IPv4 TOS byte ──────────────────────────── */
    /* We use bpf_skb_store_bytes to modify the TOS field safely.
     * TOS byte offset within the Ethernet frame = sizeof(ethhdr) + 1
     * (ip->tos is at offset 1 within the IPv4 header).
     */
    __u32 tos_offset = sizeof(struct ethhdr) + offsetof(struct iphdr, tos);
    __u8  new_tos    = (ip->tos & 0x03) | TSM_DSCP_MARK; /* preserve ECN bits */

    /* bpf_skb_store_bytes handles checksum recomputation when BPF_F_RECOMPUTE_CSUM is set */
    bpf_skb_store_bytes(skb, tos_offset, &new_tos, sizeof(new_tos),
                        BPF_F_RECOMPUTE_CSUM | BPF_F_INVALIDATE_HASH);

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
