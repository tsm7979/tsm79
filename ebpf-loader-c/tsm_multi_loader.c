/*
 * tsm_multi_loader.c — TSM Dual-XDP Program Loader with Redis Blocklist Sync
 *
 * Loads and manages two XDP programs:
 *   1. xdp_ddos.o    — DDoS mitigation (SYN flood, rate limiting, blocklist drop)
 *   2. xdp_ai_filter.o — AI traffic classification (route_local vs route_cloud)
 *
 * Program chaining via BPF_MAP_TYPE_PROG_ARRAY (tail calls):
 *   xdp_ddos is the entry point (primary XDP hook).
 *   On pass, it tail-calls xdp_ai_filter via a PROG_ARRAY map.
 *   Shared maps (ai_ips, tsm_stats, tsm_session_xdp) are pinned and reused.
 *
 * Redis blocklist sync:
 *   A background POSIX thread polls tsm:xdp:blocklist every 30s via redis-cli.
 *   New entries are inserted into the tsm_blocklist kernel map immediately.
 *   Expired entries (TTL key missing) are removed from the kernel map.
 *
 * Build:
 *   cc -O2 -Wall -Wextra -pthread -o tsm_multi_loader tsm_multi_loader.c \
 *      -lbpf -lelf -lz
 *
 * Requires: Linux >= 5.15, libbpf >= 1.0, redis-cli in PATH,
 *           CAP_NET_ADMIN, CAP_BPF (or CAP_SYS_ADMIN on older kernels)
 *
 * Usage:
 *   tsm_multi_loader --iface eth0 \
 *     --ddos-obj  /opt/tsm/bpf/xdp_ddos.o \
 *     --filter-obj /opt/tsm/bpf/xdp_ai_filter.o \
 *     [--cidrs /etc/tsm/ai_cidrs.txt] \
 *     [--redis localhost:6379] \
 *     [--pin /sys/fs/bpf/tsm] \
 *     [--control /run/tsm/loader.sock]
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <getopt.h>
#include <pthread.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

/* ── Constants ───────────────────────────────────────────────────────────── */

#define TSM_VERSION             "2.0.0"
#define TSM_PIN_DIR             "/sys/fs/bpf/tsm"
#define TSM_MAX_CIDRS           4096
#define TSM_MAX_BLOCK_ENTRIES   100000
#define BLOCKLIST_SYNC_INTERVAL 30    /* seconds between Redis syncs */

/* BPF map names (must match the SEC(".maps") declarations in BPF C code) */
#define MAP_AI_IPS          "ai_ips"
#define MAP_TSM_STATS       "tsm_stats"
#define MAP_TSM_BLOCKLIST   "tsm_blocklist"
#define MAP_TSM_RATE        "tsm_rate_buckets"
#define MAP_TSM_SYN         "tsm_syn_state"
#define MAP_TSM_SESSION_XDP "tsm_session_xdp"
#define MAP_TSM_CLASSIFY    "tsm_classify_scratch"
#define MAP_TSM_REDIRECT    "tsm_redirect_map"
#define MAP_PROG_CHAIN      "tsm_prog_chain"   /* PROG_ARRAY for tail calls */

/* XDP program entry point names */
#define PROG_DDOS_NAME      "tsm_xdp_ingress"
#define PROG_FILTER_NAME    "tsm_xdp_classify"

/* Block entry reason codes (must match xdp_ddos.c) */
#define BLOCK_REASON_MANUAL     1
#define BLOCK_REASON_TOR        2
#define BLOCK_REASON_BOTNET     3
#define BLOCK_REASON_SYN_FLOOD  4
#define BLOCK_REASON_RATELIMIT  5

/* ── Data types ──────────────────────────────────────────────────────────── */

struct lpm_key {
    __u32 prefixlen;
    __u32 addr;
};

struct ip_action {
    __u8  action;   /* 1 = intercept */
    __u8  pad[3];
};

struct block_entry {
    __u64 expiry_ns;
    __u8  reason;
    __u8  _pad[3];
};

struct cidr_entry {
    struct in_addr network;
    __u32          prefixlen;
};

/* ── Global loader state ─────────────────────────────────────────────────── */

static struct {
    /* BPF objects */
    struct bpf_object  *ddos_obj;
    struct bpf_object  *filter_obj;
    struct bpf_link    *ddos_link;      /* XDP link on iface */

    /* BPF program FDs for prog_array */
    int  ddos_prog_fd;
    int  filter_prog_fd;

    /* Shared map FDs (pinned) */
    int  fd_ai_ips;
    int  fd_stats;
    int  fd_blocklist;
    int  fd_rate;
    int  fd_syn;
    int  fd_session_xdp;
    int  fd_classify;
    int  fd_redirect;
    int  fd_prog_chain;

    /* Config */
    char iface[IFNAMSIZ];
    char ddos_obj_path[512];
    char filter_obj_path[512];
    char cidr_file[512];
    char redis_addr[256];
    char pin_path[256];
    char ctrl_path[256];
    int  ifindex;
    int  skb_mode;

    /* Control socket */
    int  ctrl_sock;

    /* Redis sync thread */
    pthread_t         sync_thread;
    volatile int      running;
    pthread_mutex_t   blocklist_lock;
} G;

/* ── Logging ─────────────────────────────────────────────────────────────── */

#define log_info(fmt, ...)  do { \
    struct timespec _ts; clock_gettime(CLOCK_REALTIME, &_ts); \
    fprintf(stdout, "[%ld.%03ld] [tsm-loader] INFO  " fmt "\n", \
        (long)_ts.tv_sec, (long)(_ts.tv_nsec/1000000), ##__VA_ARGS__); \
    fflush(stdout); \
} while (0)

#define log_warn(fmt, ...)  fprintf(stderr, "[tsm-loader] WARN  " fmt "\n", ##__VA_ARGS__)
#define log_error(fmt, ...) fprintf(stderr, "[tsm-loader] ERROR " fmt "\n", ##__VA_ARGS__)

/* ── Signal handling ─────────────────────────────────────────────────────── */

static void handle_signal(int sig) {
    (void)sig;
    G.running = 0;
}

/* ── CIDR helpers ────────────────────────────────────────────────────────── */

static int parse_cidr(const char *s, struct cidr_entry *out) {
    char buf[64];
    if (strlen(s) >= sizeof(buf)) return -1;
    strncpy(buf, s, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *slash = strchr(buf, '/');
    if (!slash) return -1;
    *slash = '\0';
    out->prefixlen = (__u32)atoi(slash + 1);
    if (out->prefixlen > 32) return -1;
    if (inet_pton(AF_INET, buf, &out->network) != 1) return -1;
    if (out->prefixlen < 32) {
        __u32 mask = htonl(~((1u << (32 - out->prefixlen)) - 1));
        out->network.s_addr &= mask;
    }
    return 0;
}

static int load_cidrs_from_file(const char *path, struct cidr_entry *out, int max) {
    FILE *f = fopen(path, "r");
    if (!f) { log_warn("cannot open CIDR file %s: %s", path, strerror(errno)); return -1; }
    char line[128];
    int count = 0;
    while (fgets(line, sizeof(line), f) && count < max) {
        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r' || line[len-1] == ' '))
            line[--len] = '\0';
        if (len == 0 || line[0] == '#') continue;
        if (parse_cidr(line, &out[count]) == 0) count++;
        else log_warn("invalid CIDR: %s", line);
    }
    fclose(f);
    return count;
}

static int populate_ai_cidrs(const struct cidr_entry *entries, int count) {
    int ok = 0, fail = 0;
    for (int i = 0; i < count; i++) {
        struct lpm_key key = { .prefixlen = entries[i].prefixlen,
                               .addr      = entries[i].network.s_addr };
        struct ip_action val = { .action = 1 };
        if (bpf_map_update_elem(G.fd_ai_ips, &key, &val, BPF_ANY) == 0) ok++;
        else { log_warn("CIDR insert %d failed: %s", i, strerror(errno)); fail++; }
    }
    log_info("AI CIDRs loaded: %d ok, %d failed", ok, fail);
    return fail == 0 ? 0 : -1;
}

/* ── Map open/pin helper ─────────────────────────────────────────────────── */

static int open_or_pin_map(struct bpf_object *obj, const char *name, const char *pin_dir) {
    char pin[512];
    snprintf(pin, sizeof(pin), "%s/%s", pin_dir, name);

    /* Reuse pinned map if already exists */
    int fd = bpf_obj_get(pin);
    if (fd >= 0) {
        log_info("reusing pinned map %s (fd=%d)", name, fd);
        return fd;
    }

    struct bpf_map *m = bpf_object__find_map_by_name(obj, name);
    if (!m) {
        log_warn("map '%s' not found in object (may be in the other object)", name);
        return -1;
    }

    fd = bpf_map__fd(m);
    if (fd < 0) { log_error("bpf_map__fd(%s): %s", name, strerror(errno)); return -1; }

    if (bpf_obj_pin(fd, pin) != 0)
        log_warn("cannot pin %s → %s: %s", name, pin, strerror(errno));
    else
        log_info("map %s pinned at %s (fd=%d)", name, pin, fd);

    return fd;
}

/* Look up a map by name in EITHER loaded object (DDoS or filter). */
static int resolve_map(const char *name) {
    int fd = -1;

    /* 1. Try to get from pin path (works if already pinned) */
    char pin[512];
    snprintf(pin, sizeof(pin), "%s/%s", G.pin_path, name);
    fd = bpf_obj_get(pin);
    if (fd >= 0) return fd;

    /* 2. Try DDoS object */
    if (G.ddos_obj) {
        struct bpf_map *m = bpf_object__find_map_by_name(G.ddos_obj, name);
        if (m) {
            fd = bpf_map__fd(m);
            if (fd >= 0) {
                bpf_obj_pin(fd, pin); /* pin for sharing */
                return fd;
            }
        }
    }

    /* 3. Try filter object */
    if (G.filter_obj) {
        struct bpf_map *m = bpf_object__find_map_by_name(G.filter_obj, name);
        if (m) {
            fd = bpf_map__fd(m);
            if (fd >= 0) {
                bpf_obj_pin(fd, pin); /* pin for sharing */
                return fd;
            }
        }
    }

    return -1;
}

/* ── XDP blocklist operations ─────────────────────────────────────────────── */

/**
 * Block an IPv4 address in the kernel XDP map.
 * expiry_s: seconds from now. 0 = permanent (set to ~136 years in nanoseconds).
 */
static int block_ip(const char *ip_str, __u8 reason, int expiry_s) {
    if (G.fd_blocklist < 0) return -1;

    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str, &addr) != 1) {
        log_warn("block_ip: invalid IP: %s", ip_str);
        return -1;
    }

    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    __u64 now_ns = (__u64)now.tv_sec * 1000000000ULL + (__u64)now.tv_nsec;

    struct block_entry entry;
    entry.reason    = reason;
    entry._pad[0] = entry._pad[1] = entry._pad[2] = 0;
    entry.expiry_ns = (expiry_s > 0)
        ? now_ns + (__u64)expiry_s * 1000000000ULL
        : UINT64_MAX;  /* permanent */

    pthread_mutex_lock(&G.blocklist_lock);
    int ret = bpf_map_update_elem(G.fd_blocklist, &addr.s_addr, &entry, BPF_ANY);
    pthread_mutex_unlock(&G.blocklist_lock);

    if (ret != 0) log_warn("block_ip %s: %s", ip_str, strerror(errno));
    return ret;
}

static int unblock_ip(const char *ip_str) {
    if (G.fd_blocklist < 0) return -1;
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str, &addr) != 1) return -1;

    pthread_mutex_lock(&G.blocklist_lock);
    int ret = bpf_map_delete_elem(G.fd_blocklist, &addr.s_addr);
    pthread_mutex_unlock(&G.blocklist_lock);
    return ret;
}

/* ── Redis blocklist sync thread ─────────────────────────────────────────── */
/*
 * Calls redis-cli (must be in PATH) to read the tsm:xdp:blocklist hash.
 * Parses HGETALL output and syncs to the kernel BPF blocklist map.
 *
 * redis-cli HGETALL tsm:xdp:blocklist output format:
 *   ip_address\n
 *   <json blob>\n
 *   ip_address\n
 *   <json blob>\n
 *   ...
 */

static void sync_blocklist_from_redis(const char *redis_addr) {
    char cmd[512];

    /* Parse host and port */
    char host[128] = "127.0.0.1";
    int  port = 6379;
    const char *colon = strrchr(redis_addr, ':');
    if (colon) {
        int len = (int)(colon - redis_addr);
        if (len < (int)sizeof(host)) {
            memcpy(host, redis_addr, len);
            host[len] = '\0';
        }
        port = atoi(colon + 1);
    } else {
        strncpy(host, redis_addr, sizeof(host) - 1);
    }

    snprintf(cmd, sizeof(cmd),
             "redis-cli -h %s -p %d HGETALL tsm:xdp:blocklist 2>/dev/null",
             host, port);

    FILE *pipe = popen(cmd, "r");
    if (!pipe) {
        log_warn("redis-cli popen failed: %s", strerror(errno));
        return;
    }

    char line[512];
    int  reading_ip = 1;  /* alternating: ip, json, ip, json, ... */
    char current_ip[64];
    int  added = 0, skipped = 0;

    while (fgets(line, sizeof(line), pipe)) {
        /* Strip trailing newline */
        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r'))
            line[--len] = '\0';
        if (len == 0) continue;

        if (reading_ip) {
            strncpy(current_ip, line, sizeof(current_ip) - 1);
            current_ip[sizeof(current_ip) - 1] = '\0';
        } else {
            /* JSON blob: extract "reason" field (simple substring search) */
            __u8 reason = BLOCK_REASON_MANUAL;
            if (strstr(line, "abuseipdb"))   reason = BLOCK_REASON_BOTNET;
            else if (strstr(line, "tor"))     reason = BLOCK_REASON_TOR;
            else if (strstr(line, "vpn"))     reason = BLOCK_REASON_BOTNET;
            else if (strstr(line, "manual"))  reason = BLOCK_REASON_MANUAL;

            /* Check if TTL key still exists (avoids blocking expired entries) */
            char chk_cmd[256];
            snprintf(chk_cmd, sizeof(chk_cmd),
                     "redis-cli -h %s -p %d EXISTS tsm:xdp:bl:%s 2>/dev/null",
                     host, port, current_ip);
            FILE *chk = popen(chk_cmd, "r");
            int exists = 0;
            if (chk) {
                char result[16];
                if (fgets(result, sizeof(result), chk)) exists = atoi(result);
                pclose(chk);
            }

            if (exists) {
                block_ip(current_ip, reason, 86400 /* 24h default */);
                added++;
            } else {
                /* Entry has expired — remove from kernel map */
                unblock_ip(current_ip);
                skipped++;
            }
        }
        reading_ip ^= 1;
    }
    pclose(pipe);

    if (added > 0 || skipped > 0) {
        log_info("Redis blocklist sync: %d entries added, %d expired removed", added, skipped);
    }
}

static void *redis_sync_thread(void *arg) {
    (void)arg;
    log_info("Redis blocklist sync thread started (interval=%ds, redis=%s)",
             BLOCKLIST_SYNC_INTERVAL, G.redis_addr);

    while (G.running) {
        sync_blocklist_from_redis(G.redis_addr);
        for (int i = 0; i < BLOCKLIST_SYNC_INTERVAL && G.running; i++)
            sleep(1);
    }
    log_info("Redis sync thread exiting");
    return NULL;
}

/* ── Control socket handler ──────────────────────────────────────────────── */
/*
 * Commands:
 *   STATUS              → loader status
 *   ADD <cidr>          → add CIDR to ai_ips LPM trie
 *   DEL <cidr>          → remove CIDR
 *   BLOCK <ip> [reason] → add IP to XDP blocklist (reason: manual/tor/botnet)
 *   UNBLOCK <ip>        → remove from blocklist
 *   RELOAD              → reload CIDR file + sync Redis blocklist
 *   STATS               → dump stat counters
 */

static void handle_ctrl_msg(const char *msg, size_t len,
                             const struct sockaddr_un *peer, socklen_t peer_len) {
    (void)len;
    char response[512];
    char cmd[32], arg1[128], arg2[64];
    int n = sscanf(msg, "%31s %127s %63s", cmd, arg1, arg2);
    if (n < 1) n = 0;

    if (strcmp(cmd, "STATUS") == 0) {
        snprintf(response, sizeof(response),
                 "OK version=%s iface=%s ddos=%s filter=%s "
                 "fd_ips=%d fd_bl=%d running=%d\n",
                 TSM_VERSION, G.iface,
                 G.ddos_obj_path[0] ? G.ddos_obj_path : "none",
                 G.filter_obj_path[0] ? G.filter_obj_path : "none",
                 G.fd_ai_ips, G.fd_blocklist, G.running);

    } else if (strcmp(cmd, "ADD") == 0 && n >= 2) {
        struct cidr_entry e;
        if (parse_cidr(arg1, &e) != 0) {
            snprintf(response, sizeof(response), "ERR invalid CIDR: %s\n", arg1);
        } else {
            struct lpm_key key = { .prefixlen = e.prefixlen, .addr = e.network.s_addr };
            struct ip_action val = { .action = 1 };
            if (G.fd_ai_ips >= 0 &&
                bpf_map_update_elem(G.fd_ai_ips, &key, &val, BPF_ANY) == 0) {
                snprintf(response, sizeof(response), "OK added %s\n", arg1);
                log_info("CTRL ADD %s", arg1);
            } else {
                snprintf(response, sizeof(response), "ERR map update failed: %s\n", strerror(errno));
            }
        }

    } else if (strcmp(cmd, "DEL") == 0 && n >= 2) {
        struct cidr_entry e;
        if (parse_cidr(arg1, &e) != 0) {
            snprintf(response, sizeof(response), "ERR invalid CIDR: %s\n", arg1);
        } else {
            struct lpm_key key = { .prefixlen = e.prefixlen, .addr = e.network.s_addr };
            if (G.fd_ai_ips >= 0 &&
                bpf_map_delete_elem(G.fd_ai_ips, &key) == 0) {
                snprintf(response, sizeof(response), "OK deleted %s\n", arg1);
            } else {
                snprintf(response, sizeof(response), "ERR not found or map error: %s\n", strerror(errno));
            }
        }

    } else if (strcmp(cmd, "BLOCK") == 0 && n >= 2) {
        __u8 reason = BLOCK_REASON_MANUAL;
        if (n >= 3) {
            if (strcmp(arg2, "tor") == 0)    reason = BLOCK_REASON_TOR;
            if (strcmp(arg2, "botnet") == 0) reason = BLOCK_REASON_BOTNET;
        }
        if (block_ip(arg1, reason, 86400) == 0) {
            snprintf(response, sizeof(response), "OK blocked %s reason=%d\n", arg1, reason);
            log_info("CTRL BLOCK %s reason=%d", arg1, reason);
        } else {
            snprintf(response, sizeof(response), "ERR block failed: %s\n", strerror(errno));
        }

    } else if (strcmp(cmd, "UNBLOCK") == 0 && n >= 2) {
        unblock_ip(arg1);
        snprintf(response, sizeof(response), "OK unblocked %s\n", arg1);
        log_info("CTRL UNBLOCK %s", arg1);

    } else if (strcmp(cmd, "RELOAD") == 0) {
        int loaded = 0;
        if (G.cidr_file[0] != '\0') {
            struct cidr_entry entries[TSM_MAX_CIDRS];
            loaded = load_cidrs_from_file(G.cidr_file, entries, TSM_MAX_CIDRS);
            if (loaded > 0 && G.fd_ai_ips >= 0)
                populate_ai_cidrs(entries, loaded);
        }
        if (G.redis_addr[0] != '\0')
            sync_blocklist_from_redis(G.redis_addr);
        snprintf(response, sizeof(response),
                 "OK reloaded %d CIDRs, synced Redis blocklist\n", loaded);

    } else if (strcmp(cmd, "STATS") == 0) {
        if (G.fd_stats < 0) {
            snprintf(response, sizeof(response), "ERR stats map not available\n");
        } else {
            /* Read first 15 stat counters */
            snprintf(response, sizeof(response), "OK stats:");
            for (__u32 i = 0; i < 15; i++) {
                __u64 val = 0;
                if (bpf_map_lookup_elem(G.fd_stats, &i, &val) == 0) {
                    char tmp[32];
                    snprintf(tmp, sizeof(tmp), " [%u]=%llu", i, (unsigned long long)val);
                    strncat(response, tmp, sizeof(response) - strlen(response) - 2);
                }
            }
            strncat(response, "\n", sizeof(response) - strlen(response) - 1);
        }

    } else {
        snprintf(response, sizeof(response),
                 "ERR unknown command. "
                 "Commands: STATUS|ADD <cidr>|DEL <cidr>|BLOCK <ip> [reason]|"
                 "UNBLOCK <ip>|RELOAD|STATS\n");
    }

    sendto(G.ctrl_sock, response, strlen(response), 0,
           (const struct sockaddr *)peer, peer_len);
}

/* ── Cleanup ─────────────────────────────────────────────────────────────── */

static void cleanup(void) {
    G.running = 0;

    if (G.ctrl_sock >= 0) {
        close(G.ctrl_sock);
        unlink(G.ctrl_path);
    }

    if (G.ddos_link) {
        bpf_link__destroy(G.ddos_link);
        G.ddos_link = NULL;
        log_info("XDP program detached from %s", G.iface);
    }

    /* Close all map FDs */
    int *fds[] = {
        &G.fd_ai_ips, &G.fd_stats, &G.fd_blocklist, &G.fd_rate,
        &G.fd_syn, &G.fd_session_xdp, &G.fd_classify, &G.fd_redirect,
        &G.fd_prog_chain, NULL
    };
    for (int i = 0; fds[i]; i++) {
        if (*fds[i] >= 0) { close(*fds[i]); *fds[i] = -1; }
    }

    if (G.ddos_obj)   { bpf_object__close(G.ddos_obj);   G.ddos_obj   = NULL; }
    if (G.filter_obj) { bpf_object__close(G.filter_obj); G.filter_obj = NULL; }

    pthread_mutex_destroy(&G.blocklist_lock);
    log_info("cleanup complete");
}

/* ── Usage ───────────────────────────────────────────────────────────────── */

static void print_usage(const char *prog) {
    fprintf(stderr,
        "TSM Multi-XDP Loader v%s\n\n"
        "Usage: %s --iface IFACE --ddos-obj PATH --filter-obj PATH [OPTIONS]\n\n"
        "Options:\n"
        "  --iface       IFACE   Network interface (required)\n"
        "  --ddos-obj    PATH    Path to xdp_ddos.o (required)\n"
        "  --filter-obj  PATH    Path to xdp_ai_filter.o (required)\n"
        "  --cidrs       FILE    AI provider CIDR list [optional]\n"
        "  --redis       HOST:PORT Redis for blocklist sync [default: 127.0.0.1:6379]\n"
        "  --pin         DIR     BPF pin dir [default: %s]\n"
        "  --control     SOCK    UNIX socket [default: /run/tsm/loader.sock]\n"
        "  --skb-mode            Use SKB XDP mode (fallback for VMs)\n"
        "  --no-redis            Disable Redis blocklist sync\n"
        "  -h, --help\n\n"
        "Environment overrides:\n"
        "  TSM_XDP_IFACE, TSM_DDOS_OBJ, TSM_FILTER_OBJ,\n"
        "  TSM_CIDR_FILE, TSM_REDIS_ADDR\n",
        TSM_VERSION, prog, TSM_PIN_DIR
    );
}

/* ── Main ────────────────────────────────────────────────────────────────── */

int main(int argc, char *argv[]) {
    /* ── Defaults ─────────────────────────────────────────────────────── */
    memset(&G, 0, sizeof(G));
    G.ctrl_sock      = -1;
    G.fd_ai_ips      = -1;
    G.fd_stats       = -1;
    G.fd_blocklist   = -1;
    G.fd_rate        = -1;
    G.fd_syn         = -1;
    G.fd_session_xdp = -1;
    G.fd_classify    = -1;
    G.fd_redirect    = -1;
    G.fd_prog_chain  = -1;
    G.ddos_prog_fd   = -1;
    G.filter_prog_fd = -1;
    G.running        = 1;

    strncpy(G.pin_path,   TSM_PIN_DIR,             sizeof(G.pin_path) - 1);
    strncpy(G.ctrl_path,  "/run/tsm/loader.sock",  sizeof(G.ctrl_path) - 1);
    strncpy(G.redis_addr, "127.0.0.1:6379",        sizeof(G.redis_addr) - 1);

    int no_redis = 0;

    /* Environment overrides */
    const char *env;
    if ((env = getenv("TSM_XDP_IFACE")))   strncpy(G.iface, env, IFNAMSIZ - 1);
    if ((env = getenv("TSM_DDOS_OBJ")))    strncpy(G.ddos_obj_path, env, sizeof(G.ddos_obj_path) - 1);
    if ((env = getenv("TSM_FILTER_OBJ")))  strncpy(G.filter_obj_path, env, sizeof(G.filter_obj_path) - 1);
    if ((env = getenv("TSM_CIDR_FILE")))   strncpy(G.cidr_file, env, sizeof(G.cidr_file) - 1);
    if ((env = getenv("TSM_REDIS_ADDR")))  strncpy(G.redis_addr, env, sizeof(G.redis_addr) - 1);

    /* ── Argument parsing ─────────────────────────────────────────────── */
    static const struct option opts[] = {
        { "iface",      required_argument, NULL, 'i' },
        { "ddos-obj",   required_argument, NULL, 'd' },
        { "filter-obj", required_argument, NULL, 'f' },
        { "cidrs",      required_argument, NULL, 'c' },
        { "redis",      required_argument, NULL, 'r' },
        { "pin",        required_argument, NULL, 'p' },
        { "control",    required_argument, NULL, 'C' },
        { "skb-mode",   no_argument,       NULL, 's' },
        { "no-redis",   no_argument,       NULL, 'n' },
        { "help",       no_argument,       NULL, 'h' },
        { NULL, 0, NULL, 0 }
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "i:d:f:c:r:p:C:snh", opts, NULL)) != -1) {
        switch (opt) {
        case 'i': strncpy(G.iface, optarg, IFNAMSIZ - 1); break;
        case 'd': strncpy(G.ddos_obj_path, optarg, sizeof(G.ddos_obj_path) - 1); break;
        case 'f': strncpy(G.filter_obj_path, optarg, sizeof(G.filter_obj_path) - 1); break;
        case 'c': strncpy(G.cidr_file, optarg, sizeof(G.cidr_file) - 1); break;
        case 'r': strncpy(G.redis_addr, optarg, sizeof(G.redis_addr) - 1); break;
        case 'p': strncpy(G.pin_path, optarg, sizeof(G.pin_path) - 1); break;
        case 'C': strncpy(G.ctrl_path, optarg, sizeof(G.ctrl_path) - 1); break;
        case 's': G.skb_mode = 1; break;
        case 'n': no_redis = 1; break;
        case 'h': print_usage(argv[0]); return 0;
        default:  print_usage(argv[0]); return 1;
        }
    }

    if (G.iface[0] == '\0' || G.ddos_obj_path[0] == '\0' || G.filter_obj_path[0] == '\0') {
        log_error("--iface, --ddos-obj, and --filter-obj are required");
        print_usage(argv[0]);
        return 1;
    }

    /* ── Signals / init ───────────────────────────────────────────────── */
    signal(SIGTERM, handle_signal);
    signal(SIGINT,  handle_signal);
    atexit(cleanup);
    pthread_mutex_init(&G.blocklist_lock, NULL);

    G.ifindex = (int)if_nametoindex(G.iface);
    if (G.ifindex == 0) {
        log_error("interface '%s' not found: %s", G.iface, strerror(errno));
        return 1;
    }

    log_info("TSM Multi-XDP Loader v%s on %s (ifindex=%d)", TSM_VERSION, G.iface, G.ifindex);

    /* Ensure BPF pin dir exists */
    if (mkdir(G.pin_path, 0700) != 0 && errno != EEXIST)
        log_warn("cannot create pin dir %s: %s", G.pin_path, strerror(errno));

    /* ── Load DDoS BPF object ─────────────────────────────────────────── */
    struct bpf_object_open_opts open_opts = { .sz = sizeof(open_opts) };

    G.ddos_obj = bpf_object__open_file(G.ddos_obj_path, &open_opts);
    if (libbpf_get_error(G.ddos_obj)) {
        log_error("cannot open %s: %s", G.ddos_obj_path, strerror(errno));
        return 1;
    }
    if (bpf_object__load(G.ddos_obj) != 0) {
        log_error("cannot load %s: %s", G.ddos_obj_path, strerror(errno));
        return 1;
    }
    log_info("DDoS object loaded: %s", G.ddos_obj_path);

    /* ── Pin shared maps from DDoS object first ───────────────────────── */
    G.fd_ai_ips    = open_or_pin_map(G.ddos_obj, MAP_AI_IPS,        G.pin_path);
    G.fd_stats     = open_or_pin_map(G.ddos_obj, MAP_TSM_STATS,     G.pin_path);
    G.fd_blocklist = open_or_pin_map(G.ddos_obj, MAP_TSM_BLOCKLIST, G.pin_path);
    G.fd_rate      = open_or_pin_map(G.ddos_obj, MAP_TSM_RATE,      G.pin_path);
    G.fd_syn       = open_or_pin_map(G.ddos_obj, MAP_TSM_SYN,       G.pin_path);

    if (G.fd_ai_ips < 0 || G.fd_blocklist < 0) {
        log_error("required maps missing from DDoS object");
        return 1;
    }

    /* ── Find and attach DDoS XDP program ─────────────────────────────── */
    struct bpf_program *ddos_prog = bpf_object__find_program_by_name(G.ddos_obj, PROG_DDOS_NAME);
    if (!ddos_prog) {
        /* Try section name fallback */
        ddos_prog = bpf_object__next_program(G.ddos_obj, NULL);
        if (!ddos_prog) { log_error("no program in DDoS object"); return 1; }
        log_warn("'%s' not found, using first program in object", PROG_DDOS_NAME);
    }

    G.ddos_link = bpf_program__attach_xdp(ddos_prog, G.ifindex);
    if (libbpf_get_error(G.ddos_link)) {
        log_warn("native XDP attach failed, trying SKB mode");
        G.ddos_link = NULL;
        __u32 flags = XDP_FLAGS_SKB_MODE;
        int prog_fd = bpf_program__fd(ddos_prog);
        if (bpf_xdp_attach(G.ifindex, prog_fd, flags, NULL) != 0) {
            log_error("XDP attach SKB mode failed: %s", strerror(errno));
            return 1;
        }
        log_info("DDoS XDP attached (SKB mode) to %s", G.iface);
    } else {
        log_info("DDoS XDP attached (native mode) to %s", G.iface);
    }
    G.ddos_prog_fd = bpf_program__fd(ddos_prog);

    /* ── Load filter BPF object ───────────────────────────────────────── */
    /*
     * The filter object shares maps with the DDoS object via pinned paths.
     * Before loading, configure shared maps to reuse the pinned FDs.
     * This way both programs operate on the same kernel maps.
     */
    G.filter_obj = bpf_object__open_file(G.filter_obj_path, &open_opts);
    if (libbpf_get_error(G.filter_obj)) {
        log_warn("cannot open %s: %s — AI filter disabled", G.filter_obj_path, strerror(errno));
        G.filter_obj = NULL;
        goto maps_loaded;
    }

    /* Reuse pinned shared maps in filter object */
    const char *shared_maps[] = {
        MAP_AI_IPS, MAP_TSM_STATS, NULL
    };
    for (int i = 0; shared_maps[i]; i++) {
        char pin[512];
        snprintf(pin, sizeof(pin), "%s/%s", G.pin_path, shared_maps[i]);
        struct bpf_map *m = bpf_object__find_map_by_name(G.filter_obj, shared_maps[i]);
        if (m) {
            bpf_map__set_pin_path(m, pin);
        }
    }

    if (bpf_object__load(G.filter_obj) != 0) {
        log_warn("cannot load %s: %s — AI filter disabled", G.filter_obj_path, strerror(errno));
        bpf_object__close(G.filter_obj);
        G.filter_obj = NULL;
        goto maps_loaded;
    }
    log_info("AI filter object loaded: %s", G.filter_obj_path);

    /* Pin filter-specific maps */
    G.fd_session_xdp = open_or_pin_map(G.filter_obj, MAP_TSM_SESSION_XDP, G.pin_path);
    G.fd_classify    = open_or_pin_map(G.filter_obj, MAP_TSM_CLASSIFY,    G.pin_path);
    G.fd_redirect    = open_or_pin_map(G.filter_obj, MAP_TSM_REDIRECT,    G.pin_path);

    /* Wire filter program into the DDoS PROG_ARRAY for tail calls */
    {
        struct bpf_program *filter_prog =
            bpf_object__find_program_by_name(G.filter_obj, PROG_FILTER_NAME);
        if (!filter_prog)
            filter_prog = bpf_object__next_program(G.filter_obj, NULL);

        if (filter_prog) {
            G.filter_prog_fd = bpf_program__fd(filter_prog);

            /* Look up the PROG_ARRAY in the DDoS object */
            struct bpf_map *chain_map =
                bpf_object__find_map_by_name(G.ddos_obj, MAP_PROG_CHAIN);
            if (chain_map) {
                G.fd_prog_chain = bpf_map__fd(chain_map);
                __u32 idx = 0;  /* index 0 = AI filter in the tail call chain */
                if (bpf_map_update_elem(G.fd_prog_chain, &idx, &G.filter_prog_fd, BPF_ANY) == 0) {
                    log_info("AI filter wired into DDoS prog_array[0] (tail calls enabled)");
                } else {
                    log_warn("prog_array update failed: %s", strerror(errno));
                }
            } else {
                log_warn("'%s' not found in DDoS object — tail call chain disabled", MAP_PROG_CHAIN);
            }
        }
    }

maps_loaded:
    /* ── Populate AI CIDRs ────────────────────────────────────────────── */
    {
        struct cidr_entry entries[TSM_MAX_CIDRS];
        int count = 0;

        if (G.cidr_file[0] != '\0') {
            count = load_cidrs_from_file(G.cidr_file, entries, TSM_MAX_CIDRS);
        }

        if (count <= 0) {
            /* Built-in defaults from architecture.md (all major AI providers) */
            const char *defaults[] = {
                /* Cloudflare (OpenAI CDN) */
                "104.18.0.0/16", "104.19.0.0/16", "104.20.0.0/16",
                "104.21.0.0/16", "162.158.0.0/15",
                /* AWS (Anthropic / Bedrock) */
                "3.208.0.0/12", "34.192.0.0/10", "52.0.0.0/11",
                "13.32.0.0/15", "13.224.0.0/14",
                /* Azure OpenAI */
                "20.33.0.0/16", "20.36.0.0/14", "40.64.0.0/10",
                /* Google Vertex AI */
                "34.64.0.0/10", "34.128.0.0/10",
                /* Mistral AI */
                "51.75.64.0/18", "51.210.0.0/16",
                /* Cohere */
                "44.195.0.0/16",
                NULL
            };
            for (const char **p = defaults; *p && count < TSM_MAX_CIDRS; p++) {
                if (parse_cidr(*p, &entries[count]) == 0) count++;
            }
            log_info("using %d built-in AI CIDRs (no --cidrs file specified)", count);
        }

        if (count > 0) populate_ai_cidrs(entries, count);
    }

    /* ── Redis sync thread ────────────────────────────────────────────── */
    if (!no_redis && G.redis_addr[0] != '\0') {
        /* Initial sync before thread */
        sync_blocklist_from_redis(G.redis_addr);
        pthread_create(&G.sync_thread, NULL, redis_sync_thread, NULL);
    } else {
        log_info("Redis blocklist sync disabled");
    }

    /* ── Control socket ───────────────────────────────────────────────── */
    {
        char ctrl_dir[256];
        strncpy(ctrl_dir, G.ctrl_path, sizeof(ctrl_dir) - 1);
        char *slash = strrchr(ctrl_dir, '/');
        if (slash && slash != ctrl_dir) { *slash = '\0'; mkdir(ctrl_dir, 0700); }

        unlink(G.ctrl_path);
        G.ctrl_sock = socket(AF_UNIX, SOCK_DGRAM, 0);
        if (G.ctrl_sock >= 0) {
            struct sockaddr_un addr = { .sun_family = AF_UNIX };
            strncpy(addr.sun_path, G.ctrl_path, sizeof(addr.sun_path) - 1);
            if (bind(G.ctrl_sock, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
                chmod(G.ctrl_path, 0600);
                fcntl(G.ctrl_sock, F_SETFL, O_NONBLOCK);
                log_info("control socket: %s", G.ctrl_path);
            } else {
                log_warn("control socket bind: %s", strerror(errno));
                close(G.ctrl_sock);
                G.ctrl_sock = -1;
            }
        }
    }

    log_info("running — SIGTERM to stop | control socket: %s", G.ctrl_path);

    /* ── Main event loop ─────────────────────────────────────────────── */
    char msgbuf[512];
    struct sockaddr_un peer;
    socklen_t peer_len;

    while (G.running) {
        if (G.ctrl_sock >= 0) {
            peer_len = sizeof(peer);
            ssize_t n = recvfrom(G.ctrl_sock, msgbuf, sizeof(msgbuf) - 1, 0,
                                 (struct sockaddr *)&peer, &peer_len);
            if (n > 0) {
                msgbuf[n] = '\0';
                handle_ctrl_msg(msgbuf, (size_t)n, &peer, peer_len);
            }
        }
        usleep(50000);
    }

    log_info("shutdown requested");
    if (G.redis_addr[0] != '\0' && !no_redis)
        pthread_join(G.sync_thread, NULL);

    return 0;
}
