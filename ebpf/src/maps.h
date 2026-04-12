/* TSMv2 — BPF map definitions shared between XDP programs and the userspace loader.
 *
 * These maps are pinned at /sys/fs/bpf/tsm/ so both the XDP program and the
 * Rust loader can reference them after the program is attached.
 *
 * Key types use __u32 for IPv4 addresses.  IPv6 support can be added later
 * by switching to a __u8[16] key with a separate map.
 */

#pragma once

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* ── Per-IP packet counters ─────────────────────────────────────────────────
 *
 * Incremented atomically for every TCP/UDP packet that passes the XDP layer
 * on the monitored port.  The Rust data plane reads this map to expose
 * per-IP counters in /metrics (tsm_xdp_packets_by_ip_total).
 *
 * Map type: BPF_MAP_TYPE_PERCPU_HASH for lock-free per-CPU updates.
 * Userspace reads sum all CPU buckets via bpf_map_lookup_elem().
 */
struct {
    __uint(type,        BPF_MAP_TYPE_PERCPU_HASH);
    __uint(key_size,    sizeof(__u32));   /* IPv4 source address            */
    __uint(value_size,  sizeof(__u64));   /* packet count                   */
    __uint(max_entries, 65536);
    __uint(map_flags,   0);
} ip_request_count SEC(".maps");

/* ── Blocked IPs ────────────────────────────────────────────────────────────
 *
 * A set of IPv4 addresses that should be dropped at the NIC with XDP_DROP.
 * The Rust data plane writes to this map (via the Unix-socket interface) when
 * a rate-limit breach or a BLOCK policy verdict with repeated violations occurs.
 *
 * Value: 1 = blocked.  Absence or 0 = allow.
 */
struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(key_size,    sizeof(__u32));   /* IPv4 source address            */
    __uint(value_size,  sizeof(__u8));    /* 1 = blocked                    */
    __uint(max_entries, 65536);
    __uint(map_flags,   0);
} ip_blocked SEC(".maps");

/* ── Port filter ────────────────────────────────────────────────────────────
 *
 * A single-entry map holding the destination TCP port to monitor.
 * Populated by the loader at attach time (default: 8080).
 * Key = 0, Value = port (host byte order).
 *
 * Using a map instead of a constant lets the Rust loader update the port
 * without recompiling the BPF program.
 */
struct {
    __uint(type,        BPF_MAP_TYPE_ARRAY);
    __uint(key_size,    sizeof(__u32));
    __uint(value_size,  sizeof(__u16));  /* TCP port in host byte order     */
    __uint(max_entries, 1);
} tsm_config SEC(".maps");

/* ── DDoS counters ──────────────────────────────────────────────────────────
 *
 * Global counters updated by the XDP program:
 *   key 0 = total packets seen
 *   key 1 = packets dropped (blocked IP)
 *   key 2 = packets passed to userspace
 *
 * The Rust loader exposes these via the Unix socket for /metrics.
 */
struct {
    __uint(type,        BPF_MAP_TYPE_ARRAY);
    __uint(key_size,    sizeof(__u32));
    __uint(value_size,  sizeof(__u64));
    __uint(max_entries, 8);
} tsm_stats SEC(".maps");

/* Stat map keys */
#define STAT_TOTAL_PACKETS   0
#define STAT_DROPPED_PACKETS 1
#define STAT_PASSED_PACKETS  2
