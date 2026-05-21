/// Distributed state store — horizontal scaling enabler.
///
/// The gap: in-memory SessionRouter + RateLimiter make each dataplane
/// instance stateful and non-scalable. This module provides Redis-backed
/// implementations that work identically from the call site but persist
/// state across multiple dataplane nodes.
///
/// Fallback: if Redis is unavailable, all operations degrade gracefully
/// to in-memory (same behaviour as before, single-node only).
///
/// Usage:
///   let store = StateStore::from_env(); // reads REDIS_URL
///   store.session_pin("sess-001", true) -> RoutePin
///   store.rate_check("192.168.1.1", 120) -> bool (true = allowed)

pub mod redis;
pub mod memory;

use std::net::IpAddr;
use crate::route::RoutePin;

// ── Unified trait interface ───────────────────────────────────────────────────

/// Distributed-safe session and rate-limit state.
pub trait DistributedState: Send + Sync {
    /// Get or create the routing pin for a session.
    /// If `sensitive = true` and session is currently `Cloud`, upgrades to `Local`.
    /// Once `Local`, never downgraded.
    fn session_pin(&self, session_id: &str, sensitive: bool) -> RoutePin;

    /// Revoke a session (on logout / session expiry).
    fn session_revoke(&self, session_id: &str);

    /// Check + consume one token from the rate limit bucket for `ip`.
    /// `rpm` = requests per minute allowed.
    /// Returns `true` if the request is allowed, `false` if rate-limited.
    fn rate_check(&self, ip: IpAddr, rpm: u32) -> bool;

    /// Name of this backend (for /health reporting).
    fn backend_name(&self) -> &'static str;
}

// ── Factory ───────────────────────────────────────────────────────────────────

/// Build a `DistributedState` from environment variables.
///
/// If `REDIS_URL` is set → uses Redis.
/// Otherwise → uses in-memory (single-node, same as prior behaviour).
pub fn from_env() -> Box<dyn DistributedState> {
    let redis_url = std::env::var("REDIS_URL").unwrap_or_default();
    if !redis_url.is_empty() {
        match redis::RedisStore::new(&redis_url) {
            Ok(store) => {
                eprintln!("[store] Redis backend connected: {}", redis_url
                    .split('@').last().unwrap_or(&redis_url));
                return Box::new(store);
            }
            Err(e) => {
                eprintln!("[store] Redis unavailable ({}): falling back to in-memory", e);
            }
        }
    }
    Box::new(memory::MemoryStore::new())
}
