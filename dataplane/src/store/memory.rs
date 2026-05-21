/// In-memory fallback implementation of DistributedState.
///
/// Semantically identical to the Redis backend but scoped to a single node.
/// Used when REDIS_URL is unset or Redis is unreachable.
///
/// Thread-safety: all state behind Mutex; fine for single-node deployments.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::route::RoutePin;
use super::DistributedState;

// ── Constants ─────────────────────────────────────────────────────────────────

const SESSION_TTL:       Duration = Duration::from_secs(4 * 3600); // 4 hours
const RATE_WINDOW:       Duration = Duration::from_secs(60);        // 1-minute window
const MAX_SESSION_SLOTS: usize   = 10_000;
const MAX_RATE_SLOTS:    usize   = 50_000;

// ── Session state ─────────────────────────────────────────────────────────────

#[derive(Clone)]
struct SessionEntry {
    pin:        RoutePin,
    last_touch: Instant,
}

// ── Rate-limit state ──────────────────────────────────────────────────────────

struct RateBucket {
    /// Ring of timestamps (as Instant) for requests in the current window.
    timestamps: Vec<Instant>,
}

impl RateBucket {
    fn new() -> Self {
        RateBucket { timestamps: Vec::with_capacity(32) }
    }

    /// Remove entries older than the window, then check if a new request fits.
    /// Returns true if allowed (and records the timestamp).
    fn check_and_consume(&mut self, limit: u32) -> bool {
        let now    = Instant::now();
        let cutoff = now.checked_sub(RATE_WINDOW).unwrap_or(now);
        self.timestamps.retain(|&t| t >= cutoff);

        if self.timestamps.len() < limit as usize {
            self.timestamps.push(now);
            true
        } else {
            false
        }
    }

    /// True if the bucket has had no activity within the window.
    fn is_idle(&self, now: Instant) -> bool {
        let cutoff = now.checked_sub(RATE_WINDOW).unwrap_or(now);
        self.timestamps.iter().all(|&t| t < cutoff)
    }
}

// ── MemoryStore ───────────────────────────────────────────────────────────────

pub struct MemoryStore {
    sessions: Mutex<HashMap<String, SessionEntry>>,
    buckets:  Mutex<HashMap<IpAddr, RateBucket>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        MemoryStore {
            sessions: Mutex::new(HashMap::new()),
            buckets:  Mutex::new(HashMap::new()),
        }
    }

    /// Evict the oldest sessions when we exceed MAX_SESSION_SLOTS.
    fn evict_sessions(map: &mut HashMap<String, SessionEntry>) {
        if map.len() <= MAX_SESSION_SLOTS { return; }

        // Collect keys sorted by last_touch ascending, drop the oldest 10%.
        let mut pairs: Vec<(String, Instant)> = map.iter()
            .map(|(k, v)| (k.clone(), v.last_touch))
            .collect();
        pairs.sort_by_key(|(_, t)| *t);

        let to_remove = (MAX_SESSION_SLOTS / 10).max(1);
        for (k, _) in pairs.into_iter().take(to_remove) {
            map.remove(&k);
        }
    }

    /// Evict idle rate buckets when we exceed MAX_RATE_SLOTS.
    fn evict_buckets(map: &mut HashMap<IpAddr, RateBucket>) {
        if map.len() <= MAX_RATE_SLOTS { return; }

        let now = Instant::now();
        map.retain(|_, b| !b.is_idle(now));

        // If still too large, just clear the remainder (extreme edge case).
        if map.len() > MAX_RATE_SLOTS {
            map.clear();
        }
    }
}

impl DistributedState for MemoryStore {
    fn session_pin(&self, session_id: &str, sensitive: bool) -> RoutePin {
        let new_pin = if sensitive { RoutePin::Local } else { RoutePin::Cloud };
        let mut map = self.sessions.lock().unwrap();

        // TTL eviction on the fast path.
        let now = Instant::now();
        if let Some(entry) = map.get_mut(session_id) {
            // Expired?
            if now.duration_since(entry.last_touch) >= SESSION_TTL {
                map.remove(session_id);
            }
        }

        Self::evict_sessions(&mut map);

        let entry = map.entry(session_id.to_owned()).or_insert(SessionEntry {
            pin:        new_pin.clone(),
            last_touch: now,
        });

        // Upgrade cloud → local; never downgrade.
        if sensitive && matches!(entry.pin, RoutePin::Cloud) {
            entry.pin = RoutePin::Local;
        }
        entry.last_touch = now;

        entry.pin.clone()
    }

    fn session_revoke(&self, session_id: &str) {
        if let Ok(mut map) = self.sessions.lock() {
            map.remove(session_id);
        }
    }

    fn rate_check(&self, ip: IpAddr, rpm: u32) -> bool {
        let mut map = self.buckets.lock().unwrap();
        Self::evict_buckets(&mut map);
        map.entry(ip).or_insert_with(RateBucket::new).check_and_consume(rpm)
    }

    fn backend_name(&self) -> &'static str { "memory" }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_starts_as_requested() {
        let store = MemoryStore::new();
        assert!(matches!(store.session_pin("s1", false), RoutePin::Cloud));
        assert!(matches!(store.session_pin("s2", true),  RoutePin::Local));
    }

    #[test]
    fn session_upgrades_cloud_to_local() {
        let store = MemoryStore::new();
        let r1 = store.session_pin("s1", false); // Cloud
        assert!(matches!(r1, RoutePin::Cloud));
        let r2 = store.session_pin("s1", true);  // upgrade → Local
        assert!(matches!(r2, RoutePin::Local));
        let r3 = store.session_pin("s1", false); // stays Local
        assert!(matches!(r3, RoutePin::Local));
    }

    #[test]
    fn session_revoke_removes_entry() {
        let store = MemoryStore::new();
        store.session_pin("s1", true);
        store.session_revoke("s1");
        // After revoke, next call should create fresh Cloud entry.
        let r = store.session_pin("s1", false);
        assert!(matches!(r, RoutePin::Cloud));
    }

    #[test]
    fn rate_check_allows_under_limit() {
        let store = MemoryStore::new();
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        for _ in 0..5 {
            assert!(store.rate_check(ip, 5));
        }
    }

    #[test]
    fn rate_check_blocks_over_limit() {
        let store = MemoryStore::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        for _ in 0..3 {
            store.rate_check(ip, 3);
        }
        assert!(!store.rate_check(ip, 3)); // 4th request must be blocked
    }

    #[test]
    fn different_ips_have_independent_buckets() {
        let store = MemoryStore::new();
        let ip1: IpAddr = "1.1.1.1".parse().unwrap();
        let ip2: IpAddr = "2.2.2.2".parse().unwrap();
        for _ in 0..2 {
            store.rate_check(ip1, 2);
        }
        assert!(!store.rate_check(ip1, 2)); // ip1 over limit
        assert!(store.rate_check(ip2, 2));  // ip2 still fine
    }
}
