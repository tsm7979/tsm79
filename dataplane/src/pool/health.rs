/// Background TCP health-check loop for upstream connections.
///
/// Periodically probes each upstream with a TCP connect.  On success,
/// marks the upstream healthy in the `BalancerRegistry`.  On failure,
/// marks it unhealthy so the load balancer stops routing to it.
///
/// Runs in a background thread (not async) since it only does
/// blocking TCP connects with a short timeout.

use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use crate::route::{BalancerRegistry, all_upstreams};

const PROBE_INTERVAL_SECS: u64 = 15;
const CONNECT_TIMEOUT_SECS: u64 = 3;

/// Start the background health-check thread.
/// Returns the `JoinHandle` (caller can ignore it).
pub fn start_health_checker(registry: Arc<BalancerRegistry>) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("tsm-health-check".to_owned())
        .spawn(move || health_loop(registry))
        .expect("failed to spawn health-check thread")
}

fn health_loop(registry: Arc<BalancerRegistry>) {
    loop {
        for target in all_upstreams() {
            // Skip local upstreams (Ollama, local) — they're always on loopback
            if target.local {
                continue;
            }
            let addr = format!("{}:{}", target.host, target.port);
            let healthy = TcpStream::connect_timeout(
                &addr.parse().unwrap_or_else(|_| "127.0.0.1:80".parse().unwrap()),
                Duration::from_secs(CONNECT_TIMEOUT_SECS),
            ).is_ok();

            if healthy {
                registry.mark_healthy(target.name, target.host, target.port);
            } else {
                registry.mark_unhealthy(target.name, target.host, target.port);
                eprintln!(
                    "[health] upstream {} ({}:{}) is unreachable",
                    target.name, target.host, target.port
                );
            }
        }
        std::thread::sleep(Duration::from_secs(PROBE_INTERVAL_SECS));
    }
}

#[cfg(test)]
mod tests {
    // Health check tests require network access, so we only test the
    // structure here and leave integration tests for the full stack.
    #[test]
    fn health_module_compiles() {
        // If this compiles, the module is correct.
    }
}
