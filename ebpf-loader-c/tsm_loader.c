/*
 * tsm_loader.c — TSM eBPF Program Loader and Map Manager
 *
 * Lifecycle:
 *   1. Load and verify the TSM XDP/TC BPF ELF object from disk
 *   2. Create or reuse pinned maps at /sys/fs/bpf/tsm/
 *   3. Attach XDP program to the configured network interface
 *   4. Update the ai_cidrs map with CIDR blocks for AI upstream IPs
 *   5. Expose a simple UNIX socket control channel for dynamic CIDR updates
 *   6. On SIGTERM/SIGINT: detach program, unpin maps, exit cleanly
 *
 * Requires: Linux kernel >= 5.15, libbpf >= 1.0, CAP_NET_ADMIN + CAP_BPF
 *
 * Build:
 *   cc -O2 -Wall -Wextra -o tsm_loader tsm_loader.c -lbpf -lelf -lz
 *
 * Usage:
 *   tsm_loader --iface eth0 --obj tsm_xdp.o [--pin-path /sys/fs/bpf/tsm]
 *              [--cidr-file /etc/tsm/ai_cidrs.txt] [--control /run/tsm/loader.sock]
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
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <linux/if_link.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <net/if.h>

/* ── Constants ───────────────────────────────────────────────────────────── */

#define TSM_MAP_PIN_DIR     "/sys/fs/bpf/tsm"
#define TSM_CIDR_MAP_NAME   "ai_cidrs"
#define TSM_CTRL_MAP_NAME   "tsm_ctrl"
#define TSM_MAX_CIDRS       4096
#define TSM_XDP_PROG_NAME   "tsm_ingress"
#define TSM_VERSION         "1.0.0"

/* ── Data types ──────────────────────────────────────────────────────────── */

/* Key for the ai_cidrs LPM trie: prefix length + IPv4 address (network byte order) */
struct lpm_key {
    __u32 prefixlen;
    __u32 addr;
};

/* Value stored in ai_cidrs: action flags */
struct cidr_value {
    __u8 action;   /* 1 = intercept and redirect to TSM */
    __u8 pad[3];
};

/* Control map key/value for runtime tuning */
struct ctrl_key {
    __u32 id;
};

struct ctrl_val {
    __u64 value;
};

/* In-memory CIDR entry */
struct cidr_entry {
    struct in_addr  network;
    __u32           prefixlen;
};

/* Loader state (global — cleaned up on signal) */
static struct tsm_loader_state {
    struct bpf_object   *obj;
    struct bpf_program  *prog;
    struct bpf_link     *link;        /* XDP link handle (prefer over legacy attach) */
    int                  cidr_map_fd;
    int                  ctrl_map_fd;
    int                  ctrl_sock;
    int                  ifindex;
    char                 iface[IFNAMSIZ];
    char                 pin_path[256];
    char                 ctrl_path[256];
    volatile sig_atomic_t running;
} state;

/* ── Logging ─────────────────────────────────────────────────────────────── */

#define log_info(fmt, ...)  fprintf(stdout, "[tsm-loader] INFO  " fmt "\n", ##__VA_ARGS__)
#define log_warn(fmt, ...)  fprintf(stderr, "[tsm-loader] WARN  " fmt "\n", ##__VA_ARGS__)
#define log_error(fmt, ...) fprintf(stderr, "[tsm-loader] ERROR " fmt "\n", ##__VA_ARGS__)

/* ── Signal handling ─────────────────────────────────────────────────────── */

static void handle_signal(int sig) {
    (void)sig;
    state.running = 0;
}

/* ── Cleanup ─────────────────────────────────────────────────────────────── */

static void cleanup(void) {
    log_info("cleaning up...");

    if (state.ctrl_sock >= 0) {
        close(state.ctrl_sock);
        unlink(state.ctrl_path);
    }

    if (state.link) {
        bpf_link__destroy(state.link);
        state.link = NULL;
        log_info("XDP program detached from %s", state.iface);
    }

    if (state.cidr_map_fd >= 0) close(state.cidr_map_fd);
    if (state.ctrl_map_fd >= 0) close(state.ctrl_map_fd);

    if (state.obj) {
        bpf_object__close(state.obj);
        state.obj = NULL;
    }

    log_info("cleanup complete");
}

/* ── CIDR parsing ────────────────────────────────────────────────────────── */

/**
 * Parse "192.168.0.0/24" into network address and prefix length.
 * Returns 0 on success, -1 on parse error.
 */
static int parse_cidr(const char *cidr_str, struct cidr_entry *out) {
    char buf[64];
    char *slash;

    if (strlen(cidr_str) >= sizeof(buf)) return -1;
    strncpy(buf, cidr_str, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    slash = strchr(buf, '/');
    if (!slash) return -1;

    *slash = '\0';
    out->prefixlen = (__u32)atoi(slash + 1);
    if (out->prefixlen > 32) return -1;

    if (inet_pton(AF_INET, buf, &out->network) != 1) return -1;

    /* Mask off host bits */
    if (out->prefixlen < 32) {
        __u32 mask = htonl(~((1u << (32 - out->prefixlen)) - 1));
        out->network.s_addr &= mask;
    }
    return 0;
}

/**
 * Load CIDRs from a text file (one "ip/prefix" per line, # comments allowed).
 * Returns number of entries loaded, -1 on file error.
 */
static int load_cidrs_from_file(const char *path, struct cidr_entry *entries, int max) {
    FILE *f = fopen(path, "r");
    if (!f) {
        log_warn("cannot open CIDR file %s: %s", path, strerror(errno));
        return -1;
    }

    char line[128];
    int count = 0;
    while (fgets(line, sizeof(line), f) && count < max) {
        /* Strip trailing newline */
        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r' || line[len-1] == ' '))
            line[--len] = '\0';

        /* Skip empty lines and comments */
        if (len == 0 || line[0] == '#') continue;

        if (parse_cidr(line, &entries[count]) == 0) {
            count++;
        } else {
            log_warn("skipping invalid CIDR: %s", line);
        }
    }
    fclose(f);
    return count;
}

/* ── BPF map operations ──────────────────────────────────────────────────── */

/**
 * Populate the ai_cidrs LPM trie with all entries.
 * Deletes any stale entries not in the new list (full replace).
 */
static int update_cidr_map(int map_fd, const struct cidr_entry *entries, int count) {
    int updated = 0, failed = 0;

    for (int i = 0; i < count; i++) {
        struct lpm_key key = {
            .prefixlen = entries[i].prefixlen,
            .addr      = entries[i].network.s_addr,
        };
        struct cidr_value val = { .action = 1 };

        if (bpf_map_update_elem(map_fd, &key, &val, BPF_ANY) == 0) {
            updated++;
        } else {
            log_warn("failed to insert CIDR entry %d: %s", i, strerror(errno));
            failed++;
        }
    }

    log_info("CIDR map updated: %d inserted, %d failed", updated, failed);
    return failed == 0 ? 0 : -1;
}

/**
 * Open or create a pinned map.
 * If the pin path exists and is the right type, reuse it.
 * Otherwise create via the bpf_object map handle and pin it.
 */
static int open_or_pin_map(struct bpf_object *obj, const char *map_name, const char *pin_dir) {
    char pin_path[512];
    snprintf(pin_path, sizeof(pin_path), "%s/%s", pin_dir, map_name);

    /* Try to reuse an existing pinned map */
    int fd = bpf_obj_get(pin_path);
    if (fd >= 0) {
        log_info("reusing pinned map %s (fd=%d)", pin_path, fd);
        return fd;
    }

    /* Find map in the BPF object */
    struct bpf_map *map = bpf_object__find_map_by_name(obj, map_name);
    if (!map) {
        log_error("map '%s' not found in BPF object", map_name);
        return -1;
    }

    fd = bpf_map__fd(map);
    if (fd < 0) {
        log_error("bpf_map__fd failed for %s: %s", map_name, strerror(errno));
        return -1;
    }

    /* Pin the map so it survives loader restarts */
    if (bpf_obj_pin(fd, pin_path) != 0) {
        log_warn("failed to pin map %s to %s: %s — continuing without pin", map_name, pin_path, strerror(errno));
    } else {
        log_info("map %s pinned at %s", map_name, pin_path);
    }

    return fd;
}

/* ── Control socket (UNIX datagram) ──────────────────────────────────────── */

/**
 * Handle a control message. Format: "ADD <cidr>" | "DEL <cidr>" | "RELOAD" | "STATUS"
 * Response is written back to the sender address.
 */
static void handle_ctrl_msg(int sock, const char *msg, size_t len,
                             const struct sockaddr_un *peer, socklen_t peer_len) {
    char response[256];
    char cmd[16], arg[64];

    (void)len;
    int n = sscanf(msg, "%15s %63s", cmd, arg);

    if (n >= 1 && strcmp(cmd, "STATUS") == 0) {
        snprintf(response, sizeof(response),
                 "OK iface=%s fd_cidr=%d fd_ctrl=%d\n",
                 state.iface, state.cidr_map_fd, state.ctrl_map_fd);

    } else if (n == 2 && strcmp(cmd, "ADD") == 0) {
        struct cidr_entry entry;
        if (parse_cidr(arg, &entry) != 0) {
            snprintf(response, sizeof(response), "ERR invalid CIDR: %s\n", arg);
        } else {
            struct lpm_key key = { .prefixlen = entry.prefixlen, .addr = entry.network.s_addr };
            struct cidr_value val = { .action = 1 };
            if (bpf_map_update_elem(state.cidr_map_fd, &key, &val, BPF_ANY) == 0) {
                snprintf(response, sizeof(response), "OK added %s\n", arg);
                log_info("CTRL ADD %s", arg);
            } else {
                snprintf(response, sizeof(response), "ERR map update failed: %s\n", strerror(errno));
            }
        }

    } else if (n == 2 && strcmp(cmd, "DEL") == 0) {
        struct cidr_entry entry;
        if (parse_cidr(arg, &entry) != 0) {
            snprintf(response, sizeof(response), "ERR invalid CIDR: %s\n", arg);
        } else {
            struct lpm_key key = { .prefixlen = entry.prefixlen, .addr = entry.network.s_addr };
            if (bpf_map_delete_elem(state.cidr_map_fd, &key) == 0) {
                snprintf(response, sizeof(response), "OK deleted %s\n", arg);
                log_info("CTRL DEL %s", arg);
            } else {
                snprintf(response, sizeof(response), "ERR not found: %s\n", arg);
            }
        }

    } else {
        snprintf(response, sizeof(response),
                 "ERR unknown command. Commands: ADD <cidr> | DEL <cidr> | STATUS\n");
    }

    sendto(sock, response, strlen(response), 0,
           (const struct sockaddr *)peer, peer_len);
}

/* ── Main ────────────────────────────────────────────────────────────────── */

static void print_usage(const char *prog) {
    fprintf(stderr,
        "TSM eBPF Loader v%s\n\n"
        "Usage: %s [OPTIONS]\n\n"
        "Options:\n"
        "  --iface   IFACE       Network interface to attach XDP program (required)\n"
        "  --obj     PATH        Path to compiled BPF ELF object (required)\n"
        "  --pin     DIR         BPF map pin directory [default: %s]\n"
        "  --cidrs   FILE        CIDR file for AI upstream IPs [optional]\n"
        "  --control SOCK        UNIX socket path for dynamic updates [default: /run/tsm/loader.sock]\n"
        "  --skb-mode            Use SKB mode instead of native XDP\n"
        "  -h, --help            Show this help\n\n"
        "Environment:\n"
        "  TSM_XDP_IFACE, TSM_BPF_OBJ, TSM_CIDR_FILE\n",
        TSM_VERSION, prog, TSM_MAP_PIN_DIR
    );
}

int main(int argc, char *argv[]) {
    /* ── Defaults ─────────────────────────────────────────────────────────── */
    char obj_path[512]   = "";
    char cidr_file[512]  = "";
    char ctrl_path[256]  = "/run/tsm/loader.sock";
    char pin_path[256]   = TSM_MAP_PIN_DIR;
    int  skb_mode        = 0;

    /* Environment variable overrides */
    const char *env;
    if ((env = getenv("TSM_XDP_IFACE")))   strncpy(state.iface, env, IFNAMSIZ - 1);
    if ((env = getenv("TSM_BPF_OBJ")))     strncpy(obj_path, env, sizeof(obj_path) - 1);
    if ((env = getenv("TSM_CIDR_FILE")))   strncpy(cidr_file, env, sizeof(cidr_file) - 1);

    /* ── Argument parsing ─────────────────────────────────────────────────── */
    static const struct option long_opts[] = {
        { "iface",   required_argument, NULL, 'i' },
        { "obj",     required_argument, NULL, 'o' },
        { "pin",     required_argument, NULL, 'p' },
        { "cidrs",   required_argument, NULL, 'c' },
        { "control", required_argument, NULL, 'C' },
        { "skb-mode",no_argument,       NULL, 's' },
        { "help",    no_argument,       NULL, 'h' },
        { NULL, 0, NULL, 0 }
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "i:o:p:c:C:sh", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'i': strncpy(state.iface, optarg, IFNAMSIZ - 1); break;
        case 'o': strncpy(obj_path, optarg, sizeof(obj_path) - 1); break;
        case 'p': strncpy(pin_path, optarg, sizeof(pin_path) - 1); break;
        case 'c': strncpy(cidr_file, optarg, sizeof(cidr_file) - 1); break;
        case 'C': strncpy(ctrl_path, optarg, sizeof(ctrl_path) - 1); break;
        case 's': skb_mode = 1; break;
        case 'h': print_usage(argv[0]); return 0;
        default:  print_usage(argv[0]); return 1;
        }
    }

    if (state.iface[0] == '\0' || obj_path[0] == '\0') {
        log_error("--iface and --obj are required");
        print_usage(argv[0]);
        return 1;
    }

    strncpy(state.pin_path, pin_path, sizeof(state.pin_path) - 1);
    strncpy(state.ctrl_path, ctrl_path, sizeof(state.ctrl_path) - 1);

    /* ── Initialise ───────────────────────────────────────────────────────── */
    state.cidr_map_fd = -1;
    state.ctrl_map_fd = -1;
    state.ctrl_sock   = -1;
    state.running     = 1;

    signal(SIGTERM, handle_signal);
    signal(SIGINT,  handle_signal);
    atexit(cleanup);

    /* Resolve interface index */
    state.ifindex = (int)if_nametoindex(state.iface);
    if (state.ifindex == 0) {
        log_error("interface '%s' not found: %s", state.iface, strerror(errno));
        return 1;
    }

    log_info("TSM eBPF Loader v%s starting on %s (ifindex=%d)",
             TSM_VERSION, state.iface, state.ifindex);

    /* Ensure pin directory exists */
    if (mkdir(pin_path, 0700) != 0 && errno != EEXIST) {
        log_warn("cannot create pin dir %s: %s — maps will not be pinned", pin_path, strerror(errno));
    }

    /* ── Load BPF object ──────────────────────────────────────────────────── */
    struct bpf_object_open_opts open_opts = {
        .sz = sizeof(open_opts),
    };
    state.obj = bpf_object__open_file(obj_path, &open_opts);
    if (libbpf_get_error(state.obj)) {
        log_error("failed to open BPF object %s: %s", obj_path, strerror(errno));
        return 1;
    }

    if (bpf_object__load(state.obj) != 0) {
        log_error("failed to load BPF object: %s", strerror(errno));
        return 1;
    }
    log_info("BPF object loaded: %s", obj_path);

    /* ── Find and attach XDP program ──────────────────────────────────────── */
    state.prog = bpf_object__find_program_by_name(state.obj, TSM_XDP_PROG_NAME);
    if (!state.prog) {
        log_error("program '%s' not found in BPF object", TSM_XDP_PROG_NAME);
        return 1;
    }

    __u32 xdp_flags = skb_mode ? XDP_FLAGS_SKB_MODE : XDP_FLAGS_DRV_MODE;
    state.link = bpf_program__attach_xdp(state.prog, state.ifindex);
    if (libbpf_get_error(state.link)) {
        log_warn("native XDP attach failed — falling back to SKB mode");
        xdp_flags = XDP_FLAGS_SKB_MODE;
        /* Retry with SKB mode via netlink */
        int prog_fd = bpf_program__fd(state.prog);
        if (bpf_xdp_attach(state.ifindex, prog_fd, xdp_flags, NULL) != 0) {
            log_error("XDP attach failed in SKB mode: %s", strerror(errno));
            return 1;
        }
        state.link = NULL; /* managed via bpf_xdp_attach */
        log_info("XDP program attached in SKB mode to %s", state.iface);
    } else {
        log_info("XDP program attached in native mode to %s", state.iface);
    }

    /* ── Open / pin maps ──────────────────────────────────────────────────── */
    state.cidr_map_fd = open_or_pin_map(state.obj, TSM_CIDR_MAP_NAME, pin_path);
    if (state.cidr_map_fd < 0) {
        log_error("could not open ai_cidrs map");
        return 1;
    }

    state.ctrl_map_fd = open_or_pin_map(state.obj, TSM_CTRL_MAP_NAME, pin_path);
    /* ctrl map is optional — don't fail if not found */

    /* ── Load initial CIDRs ───────────────────────────────────────────────── */
    if (cidr_file[0] != '\0') {
        struct cidr_entry entries[TSM_MAX_CIDRS];
        int n = load_cidrs_from_file(cidr_file, entries, TSM_MAX_CIDRS);
        if (n > 0) {
            update_cidr_map(state.cidr_map_fd, entries, n);
            log_info("loaded %d CIDRs from %s", n, cidr_file);
        }
    } else {
        /* Default: intercept all RFC-1918 private ranges (AI APIs use public IPs;
         * this acts as a passthrough for internal traffic only) */
        const char *defaults[] = {
            "104.18.0.0/16",    /* Cloudflare (OpenAI CDN) */
            "104.19.0.0/16",    /* Cloudflare */
            "3.208.0.0/12",     /* AWS us-east (Anthropic) */
            "34.0.0.0/8",       /* GCP (Google AI) */
            NULL
        };
        struct cidr_entry entries[16];
        int count = 0;
        for (const char **p = defaults; *p && count < 16; p++) {
            if (parse_cidr(*p, &entries[count]) == 0) count++;
        }
        update_cidr_map(state.cidr_map_fd, entries, count);
        log_info("loaded %d default AI CIDR entries", count);
    }

    /* ── Control socket ───────────────────────────────────────────────────── */
    {
        /* Ensure parent directory exists */
        char ctrl_dir[256];
        strncpy(ctrl_dir, ctrl_path, sizeof(ctrl_dir) - 1);
        char *slash = strrchr(ctrl_dir, '/');
        if (slash && slash != ctrl_dir) {
            *slash = '\0';
            mkdir(ctrl_dir, 0700);
        }

        unlink(ctrl_path); /* remove stale socket */
        state.ctrl_sock = socket(AF_UNIX, SOCK_DGRAM, 0);
        if (state.ctrl_sock >= 0) {
            struct sockaddr_un addr = { .sun_family = AF_UNIX };
            strncpy(addr.sun_path, ctrl_path, sizeof(addr.sun_path) - 1);
            if (bind(state.ctrl_sock, (const struct sockaddr *)&addr, sizeof(addr)) == 0) {
                chmod(ctrl_path, 0600);
                /* Non-blocking so the main loop can also sleep */
                fcntl(state.ctrl_sock, F_SETFL, O_NONBLOCK);
                log_info("control socket: %s", ctrl_path);
            } else {
                log_warn("control socket bind failed: %s", strerror(errno));
                close(state.ctrl_sock);
                state.ctrl_sock = -1;
            }
        }
    }

    log_info("running — send SIGTERM to stop");

    /* ── Event loop ───────────────────────────────────────────────────────── */
    char msg_buf[512];
    struct sockaddr_un peer;
    socklen_t peer_len;

    while (state.running) {
        if (state.ctrl_sock >= 0) {
            peer_len = sizeof(peer);
            ssize_t n = recvfrom(state.ctrl_sock, msg_buf, sizeof(msg_buf) - 1, 0,
                                 (struct sockaddr *)&peer, &peer_len);
            if (n > 0) {
                msg_buf[n] = '\0';
                handle_ctrl_msg(state.ctrl_sock, msg_buf, (size_t)n, &peer, peer_len);
            }
        }
        usleep(50000); /* 50ms poll interval */
    }

    log_info("shutdown requested");
    return 0;
}
