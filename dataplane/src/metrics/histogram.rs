use std::sync::atomic::{AtomicU64, Ordering};

/// Fixed-bucket latency histogram.
///
/// Buckets are specified at construction time as upper bounds in milliseconds.
/// Uses AtomicU64 for each bucket count — no locks on the hot path.
pub struct Histogram {
    pub name:    &'static str,
    pub help:    &'static str,
    /// Upper-bound values for each bucket (milliseconds, ascending)
    pub bounds:  &'static [f64],
    /// Count per bucket (index matches bounds; last bucket = +Inf)
    counts:      Vec<AtomicU64>,
    /// Running sum for average calculation
    sum_us:      AtomicU64,
    /// Total observation count
    total:       AtomicU64,
}

impl Histogram {
    pub fn new(name: &'static str, help: &'static str, bounds: &'static [f64]) -> Self {
        let counts = (0..=bounds.len()).map(|_| AtomicU64::new(0)).collect();
        Histogram { name, help, bounds, counts, sum_us: AtomicU64::new(0), total: AtomicU64::new(0) }
    }

    /// Record a latency observation in milliseconds.
    pub fn observe(&self, value_ms: f64) {
        self.total.fetch_add(1, Ordering::Relaxed);
        self.sum_us.fetch_add((value_ms * 1_000.0) as u64, Ordering::Relaxed);

        // Find the first bucket whose upper bound >= value; increment it.
        // Also increment all higher buckets (cumulative histogram semantics).
        let bucket = self.bounds.partition_point(|&b| b < value_ms);
        for i in bucket..self.counts.len() {
            self.counts[i].fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn count(&self) -> u64 {
        self.total.load(Ordering::Relaxed)
    }

    pub fn sum_ms(&self) -> f64 {
        self.sum_us.load(Ordering::Relaxed) as f64 / 1_000.0
    }

    /// Iterate over (upper_bound, cumulative_count) pairs.
    /// The final entry is (+Inf, total_count).
    pub fn buckets(&self) -> Vec<(f64, u64)> {
        let mut out = Vec::with_capacity(self.counts.len());
        for (i, bound) in self.bounds.iter().enumerate() {
            out.push((*bound, self.counts[i].load(Ordering::Relaxed)));
        }
        out.push((f64::INFINITY, self.total.load(Ordering::Relaxed)));
        out
    }
}

/// Standard latency buckets for AI proxy use: 1ms to 5000ms
pub const LATENCY_BOUNDS_MS: &[f64] = &[
    1.0, 2.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2500.0, 5000.0,
];

/// Detector-specific buckets: tighter range
pub const DETECTOR_BOUNDS_MS: &[f64] = &[
    0.5, 1.0, 2.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn histogram_basic() {
        let h = Histogram::new("latency", "Request latency", LATENCY_BOUNDS_MS);
        h.observe(3.0);
        h.observe(15.0);
        h.observe(600.0);

        assert_eq!(h.count(), 3);
        // 3ms falls in <=5ms bucket
        let buckets = h.buckets();
        let b5 = buckets.iter().find(|(b, _)| *b == 5.0).unwrap();
        assert_eq!(b5.1, 1);
        // 600ms falls in <=1000ms bucket
        let b1000 = buckets.iter().find(|(b, _)| *b == 1000.0).unwrap();
        assert_eq!(b1000.1, 2); // cumulative: 3ms + 600ms both <= 1000ms
    }

    #[test]
    fn inf_bucket_equals_total() {
        let h = Histogram::new("t", "test", LATENCY_BOUNDS_MS);
        h.observe(1.0);
        h.observe(9999.0); // above all bounds
        let buckets = h.buckets();
        let inf = buckets.last().unwrap();
        assert_eq!(inf.0, f64::INFINITY);
        assert_eq!(inf.1, 2);
    }
}
