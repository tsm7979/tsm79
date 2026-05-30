/// Round-robin load balancer with per-upstream health tracking.
///
/// For each upstream name, maintains a list of socket addresses and an
/// atomic index that advances on each `next()` call.  Unhealthy addresses
/// are skipped but not permanently removed; the health-check loop in
/// `pool/health.rs` flips them back.
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

/// A single address entry in a balancer slot.
pub struct AddrSlot {
    pub host:    String,
    pub port:    u16,
    pub healthy: AtomicBool,
}

impl AddrSlot {
    pub fn new(host: &str, port: u16) -> Arc<Self> {
        Arc::new(AddrSlot {
            host:    host.to_owned(),
            port,
            healthy: AtomicBool::new(true),
        })
    }
}

/// A round-robin balancer for one upstream (e.g. all OpenAI endpoints).
pub struct LoadBalancer {
    slots: Vec<Arc<AddrSlot>>,
    next:  AtomicUsize,
}

impl LoadBalancer {
    /// Create a balancer with the given set of addresses.
    /// All slots start healthy.
    pub fn new(addrs: &[(&str, u16)]) -> Self {
        let slots = addrs.iter().map(|(h, p)| AddrSlot::new(h, *p)).collect();
        LoadBalancer { slots, next: AtomicUsize::new(0) }
    }

    /// Return the next healthy slot, cycling round-robin.
    /// Returns `None` if all slots are unhealthy.
    pub fn next(&self) -> Option<Arc<AddrSlot>> {
        let len = self.slots.len();
        if len == 0 {
            return None;
        }
        // Try each slot at most `len` times
        for _ in 0..len {
            let idx = self.next.fetch_add(1, Ordering::Relaxed) % len;
            let slot = &self.slots[idx];
            if slot.healthy.load(Ordering::Relaxed) {
                return Some(Arc::clone(slot));
            }
        }
        None
    }

    /// Mark a slot as unhealthy (called by the health-check loop or
    /// when a connection attempt fails).
    pub fn mark_unhealthy(&self, host: &str, port: u16) {
        for slot in &self.slots {
            if slot.host == host && slot.port == port {
                slot.healthy.store(false, Ordering::Relaxed);
                return;
            }
        }
    }

    /// Mark a slot as healthy again (called by the health-check loop).
    pub fn mark_healthy(&self, host: &str, port: u16) {
        for slot in &self.slots {
            if slot.host == host && slot.port == port {
                slot.healthy.store(true, Ordering::Relaxed);
                return;
            }
        }
    }

    /// Return the count of currently healthy slots.
    pub fn healthy_count(&self) -> usize {
        self.slots.iter().filter(|s| s.healthy.load(Ordering::Relaxed)).count()
    }
}

/// A registry of named balancers — one per upstream.
pub struct BalancerRegistry {
    entries: Vec<(String, LoadBalancer)>,
}

impl BalancerRegistry {
    pub fn new() -> Self {
        // Populate from the static upstream table.
        use super::registry::all_upstreams;
        let entries = all_upstreams()
            .iter()
            .map(|t| {
                let lb = LoadBalancer::new(&[(&t.host, t.port)]);
                (t.name.to_owned(), lb)
            })
            .collect();
        BalancerRegistry { entries }
    }

    /// Get the next healthy address for a named upstream.
    pub fn next_for(&self, upstream_name: &str) -> Option<(String, u16)> {
        for (name, lb) in &self.entries {
            if name == upstream_name {
                return lb.next().map(|slot| (slot.host.clone(), slot.port));
            }
        }
        None
    }

    pub fn mark_unhealthy(&self, upstream_name: &str, host: &str, port: u16) {
        for (name, lb) in &self.entries {
            if name == upstream_name {
                lb.mark_unhealthy(host, port);
                return;
            }
        }
    }

    pub fn mark_healthy(&self, upstream_name: &str, host: &str, port: u16) {
        for (name, lb) in &self.entries {
            if name == upstream_name {
                lb.mark_healthy(host, port);
                return;
            }
        }
    }
}

impl Default for BalancerRegistry {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_robin_cycles() {
        let lb = LoadBalancer::new(&[("a.com", 443), ("b.com", 443), ("c.com", 443)]);
        let h0 = lb.next().unwrap().host.clone();
        let h1 = lb.next().unwrap().host.clone();
        let h2 = lb.next().unwrap().host.clone();
        let h3 = lb.next().unwrap().host.clone(); // wraps back
        assert_ne!(h0, h1);
        assert_ne!(h1, h2);
        assert_eq!(h0, h3);
    }

    #[test]
    fn skips_unhealthy() {
        let lb = LoadBalancer::new(&[("a.com", 443), ("b.com", 443)]);
        lb.mark_unhealthy("a.com", 443);
        // All next() calls should return b.com
        for _ in 0..4 {
            let slot = lb.next().unwrap();
            assert_eq!(slot.host, "b.com");
        }
    }

    #[test]
    fn all_unhealthy_returns_none() {
        let lb = LoadBalancer::new(&[("a.com", 443)]);
        lb.mark_unhealthy("a.com", 443);
        assert!(lb.next().is_none());
    }

    #[test]
    fn mark_healthy_restores() {
        let lb = LoadBalancer::new(&[("a.com", 443)]);
        lb.mark_unhealthy("a.com", 443);
        assert!(lb.next().is_none());
        lb.mark_healthy("a.com", 443);
        assert!(lb.next().is_some());
    }

    #[test]
    fn healthy_count_tracks_state() {
        let lb = LoadBalancer::new(&[("a.com", 443), ("b.com", 443)]);
        assert_eq!(lb.healthy_count(), 2);
        lb.mark_unhealthy("a.com", 443);
        assert_eq!(lb.healthy_count(), 1);
    }
}
