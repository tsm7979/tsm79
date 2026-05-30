/// TSMv2 eBPF/XDP Loader
///
/// Loads the compiled BPF object files (ingress.o, egress.o), attaches them
/// to the specified network interface, and exposes a Unix-domain socket so the
/// Rust data plane can read/write BPF maps (e.g., block an IP or read counters).
///
/// All BPF operations go through the `bpf(2)` syscall via `libc::syscall`.
/// No libbpf crate — zero external dependencies beyond `libc`.
///
/// Usage:
///   tsm-ebpf-loader --iface eth0 [--port 8080] [--socket /run/tsm/ebpf.sock]
///
/// Requirements:
///   - Root / CAP_NET_ADMIN + CAP_BPF (or CAP_SYS_ADMIN on older kernels)
///   - Kernel ≥ 5.7 for BPF_LINK_CREATE XDP (falls back to setsockopt on older)
///   - BPF object files at ./bpf/ingress.o and ./bpf/egress.o
///     (produced by `make install` in ../ebpf/)

use std::ffi::CString;
use std::os::unix::io::RawFd;
use std::path::Path;

mod bpf;
mod maps;
mod socket;

use bpf::{load_program, attach_xdp, BpfObj};
use maps::{BpfMap, MapOp};
use socket::run_control_socket;

// ── CLI args (no clap — stdlib only) ─────────────────────────────────────────

struct Args {
    iface:    String,
    port:     u16,
    sock:     String,
    ingress:  String,
    egress:   String,
}

impl Args {
    fn parse() -> Self {
        let args: Vec<String> = std::env::args().collect();
        let mut iface   = String::from("lo");
        let mut port    = 8080u16;
        let mut sock    = String::from("/run/tsm/ebpf.sock");
        let mut ingress = String::from("bpf/ingress.o");
        let mut egress  = String::from("bpf/egress.o");
        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "--iface"   => { i += 1; if i < args.len() { iface   = args[i].clone(); } }
                "--port"    => { i += 1; if i < args.len() { port    = args[i].parse().unwrap_or(8080); } }
                "--socket"  => { i += 1; if i < args.len() { sock    = args[i].clone(); } }
                "--ingress" => { i += 1; if i < args.len() { ingress = args[i].clone(); } }
                "--egress"  => { i += 1; if i < args.len() { egress  = args[i].clone(); } }
                "--help" | "-h" => {
                    eprintln!("Usage: tsm-ebpf-loader [--iface IFACE] [--port PORT] [--socket PATH] [--ingress OBJ] [--egress OBJ]");
                    std::process::exit(0);
                }
                other => eprintln!("[loader] unknown arg: {}", other),
            }
            i += 1;
        }
        Args { iface, port, sock, ingress, egress }
    }
}

// ── Main ──────────────────────────────────────────────────────────────────────

fn main() {
    let args = Args::parse();

    eprintln!("[loader] TSMv2 eBPF loader starting");
    eprintln!("[loader] interface : {}", args.iface);
    eprintln!("[loader] port      : {}", args.port);
    eprintln!("[loader] socket    : {}", args.sock);

    // ── Verify BPF object files exist ─────────────────────────────────────
    for path in &[&args.ingress, &args.egress] {
        if !Path::new(path).exists() {
            eprintln!("[loader] ERROR: BPF object not found: {}", path);
            eprintln!("[loader] Run `make install` in the ebpf/ directory first.");
            std::process::exit(1);
        }
    }

    // ── Load ingress XDP program ───────────────────────────────────────────
    let ingress_obj = match bpf::parse_elf(&args.ingress) {
        Ok(obj)  => obj,
        Err(e)   => { eprintln!("[loader] failed to parse {}: {}", args.ingress, e); std::process::exit(1); }
    };

    let prog_fd = match load_program(&ingress_obj) {
        Ok(fd)  => fd,
        Err(e)  => { eprintln!("[loader] failed to load XDP program: {}", e); std::process::exit(1); }
    };
    eprintln!("[loader] XDP program loaded, fd={}", prog_fd);

    // ── Attach XDP to interface ────────────────────────────────────────────
    let ifindex = get_ifindex(&args.iface).unwrap_or_else(|| {
        eprintln!("[loader] interface '{}' not found", args.iface);
        std::process::exit(1);
    });

    if let Err(e) = attach_xdp(prog_fd, ifindex) {
        eprintln!("[loader] XDP attach failed: {} (need root + CAP_NET_ADMIN)", e);
        std::process::exit(1);
    }
    eprintln!("[loader] XDP attached to {} (ifindex={})", args.iface, ifindex);

    // ── Configure tsm_config map (port) ───────────────────────────────────
    if let Some(map_fd) = ingress_obj.map_fd("tsm_config") {
        let key: u32 = 0;
        let val: u16 = args.port;
        maps::update_u32_u16(map_fd, key, val);
        eprintln!("[loader] tsm_config[0] = {} (TSM port)", args.port);
    }

    // ── Run control socket ─────────────────────────────────────────────────
    // The control socket allows the data plane to:
    //   BLOCK <ip>       — add to ip_blocked map
    //   UNBLOCK <ip>     — remove from ip_blocked map
    //   STATS            — read tsm_stats counters
    //   COUNT <ip>       — read ip_request_count for one IP
    eprintln!("[loader] control socket at {}", args.sock);
    run_control_socket(&args.sock, &ingress_obj);

    // Clean up: detach XDP on exit (handled by kernel on process death anyway)
    unsafe { libc::close(prog_fd); }
}

// ── Interface index lookup ────────────────────────────────────────────────────

fn get_ifindex(iface: &str) -> Option<u32> {
    let name = CString::new(iface).ok()?;
    let idx  = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if idx == 0 { None } else { Some(idx) }
}
