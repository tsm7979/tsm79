/// TSMv2 — Sovereign AI Infrastructure Data Plane
///
/// Entry point.  Binds the listening socket, initialises all subsystems,
/// starts the health-check background thread, and drives the accept loop.
/// Each incoming connection is handled on its own OS thread (thread-per-connection).
/// The async executor is available for future i/o_uring-driven work.
///
/// No tokio.  No hyper.  No axum.  Every byte owned.

mod config;
mod metrics;
mod audit;
mod detect;
mod policy;
mod route;
mod pool;
mod http;
mod ai;
mod tls;
mod io;
mod pipeline;
mod telemetry;

use std::net::TcpListener;
use std::os::unix::io::{AsRawFd, IntoRawFd, RawFd};
use std::sync::Arc;
use std::time::Duration;

extern crate libc;

use config::Config;
use audit::AuditLog;
use pool::ConnPool;
use policy::PolicyEngine;
use route::BalancerRegistry;
use pipeline::RateLimiter;
#[allow(unused_imports)]
use io::{set_nonblocking, set_reuseaddr, set_nodelay};

// ── Health check (used by Docker HEALTHCHECK CMD) ────────────────────────────

/// Perform a fast liveness check: open a TCP connection to localhost:8080,
/// send a minimal HTTP/1.0 GET /health, and return 0 on "200 OK", 1 otherwise.
///
/// This is compiled into the same binary so distroless images (no wget/curl)
/// can still run `tsm-dataplane --health-check` as the HEALTHCHECK command.
fn do_health_check() -> i32 {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::time::Duration;

    let req = b"GET /health HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    let Ok(mut s) = TcpStream::connect("127.0.0.1:8080") else { return 1; };
    s.set_read_timeout(Some(Duration::from_secs(2))).ok();
    if s.write_all(req).is_err() { return 1; }
    let mut buf = [0u8; 128];
    match s.read(&mut buf) {
        Ok(n) if n >= 12 => {
            // Accept any HTTP 2xx
            if buf[..n].starts_with(b"HTTP/")
                && buf[..n].windows(4).any(|w| w == b" 200")
            {
                0
            } else {
                1
            }
        }
        _ => 1,
    }
}

// ── Main ──────────────────────────────────────────────────────────────────────

fn main() {
    // When invoked as `tsm-dataplane --health-check` (used by Docker HEALTHCHECK),
    // do a quick liveness probe against the running instance and exit.
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 && args[1] == "--health-check" {
        std::process::exit(do_health_check());
    }

    let config = Arc::new(Config::from_env());

    if config.log_level == "debug" {
        telemetry::enable_debug();
    }

    print_banner(&config);

    // ── Audit log ─────────────────────────────────────────────────────────────
    let audit = Arc::new(
        AuditLog::open(&config.audit_log_path, &config.audit_secret)
            .expect("failed to open audit log"),
    );

    // ── Connection pool ───────────────────────────────────────────────────────
    let pool = Arc::new(ConnPool::new(config.pool_max_idle));

    // ── Policy engine ─────────────────────────────────────────────────────────
    let policy = Arc::new(PolicyEngine::new());
    policy.load_builtin_rules();

    // ── Policy hot-reload (polls control plane if configured) ─────────────────
    crate::policy::hotreload::start(config.clone(), policy.clone());

    // ── Rate limiter ──────────────────────────────────────────────────────────
    let rate_limiter = Arc::new(RateLimiter::new(config.rate_limit));

    // ── Balancer registry (for health checker) ────────────────────────────────
    let registry = Arc::new(BalancerRegistry::new());
    let _health_handle = pool::start_health_checker(registry.clone());

    // ── TCP listener ──────────────────────────────────────────────────────────
    let listener = TcpListener::bind(config.listen_addr)
        .unwrap_or_else(|e| panic!("failed to bind {}: {}", config.listen_addr, e));

    set_reuseaddr(listener.as_raw_fd())
        .unwrap_or_else(|e| eprintln!("[main] SO_REUSEADDR failed: {}", e));

    eprintln!("[main] listening on {}", config.listen_addr);

    // ── Accept loop ───────────────────────────────────────────────────────────
    accept_loop(listener, config, pool, audit, policy, rate_limiter);
}

// ── Accept loop ───────────────────────────────────────────────────────────────

/// Accepts connections in a loop, spawning one OS thread per connection.
///
/// Thread-per-connection is appropriate here because each pipeline call is
/// blocking I/O (read → detect → forward → write).  The async executor handles
/// *within-connection* concurrency for multiplexed HTTP/2 streams in a future
/// iteration; the connection granularity is coarse enough that OS threads work.
fn accept_loop(
    listener:     TcpListener,
    config:       Arc<Config>,
    pool:         Arc<ConnPool>,
    audit:        Arc<AuditLog>,
    policy:       Arc<PolicyEngine>,
    rate_limiter: Arc<RateLimiter>,
) {
    loop {
        let (stream, peer) = match listener.accept() {
            Ok(pair) => pair,
            Err(e) => {
                eprintln!("[accept] error: {}", e);
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
        };

        if config.log_level == "debug" {
            eprintln!("[accept] new connection from {}", peer);
        }

        // Configure TCP options on the accepted socket
        let fd: RawFd = {
            let raw = stream.as_raw_fd();
            let _ = set_nodelay(raw);
            stream.into_raw_fd()
        };

        // Clone Arcs for the worker thread
        let config2       = config.clone();
        let pool2         = pool.clone();
        let audit2        = audit.clone();
        let policy2       = policy.clone();
        let rate_limiter2 = rate_limiter.clone();

        // Spawn worker thread for this connection
        match std::thread::Builder::new()
            .name(format!("tsm-conn-{}", peer))
            .spawn(move || {
                // keep-alive loop: one thread handles multiple pipelined requests
                let mut keep_alive = true;
                while keep_alive {
                    keep_alive = pipeline::handle_connection(
                        fd,
                        config2.clone(),
                        pool2.clone(),
                        audit2.clone(),
                        policy2.clone(),
                        rate_limiter2.clone(),
                    );
                }
                // fd is closed by pipeline when it returns false
            }) {
            Ok(_handle) => { /* thread is running */ }
            Err(e) => {
                eprintln!("[accept] thread spawn failed: {}", e);
                unsafe { libc::close(fd); }
            }
        }
    }
}

// ── Banner ────────────────────────────────────────────────────────────────────

fn print_banner(config: &Config) {
    eprintln!("╔══════════════════════════════════════════════════════════╗");
    eprintln!("║      TSMv2 — Sovereign AI Data Plane  (Rust)            ║");
    eprintln!("╠══════════════════════════════════════════════════════════╣");
    eprintln!("║  listen   : {:<44} ║", config.listen_addr);
    eprintln!("║  detector : {:<44} ║", config.detector_url);
    eprintln!("║  audit    : {:<44} ║", config.audit_log_path);
    eprintln!("║  pool     : {} idle/upstream{:<29} ║", config.pool_max_idle, "");
    eprintln!("║  on error : {:?}{:<43} ║", config.detector_failure_mode, "");
    eprintln!("╚══════════════════════════════════════════════════════════╝");
}
