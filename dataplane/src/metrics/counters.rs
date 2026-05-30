use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// A named, thread-safe monotonically increasing counter backed by AtomicU64.
pub struct Counter {
    pub name:  &'static str,
    pub help:  &'static str,
    pub value: AtomicU64,
}

impl Counter {
    pub const fn new(name: &'static str, help: &'static str) -> Self {
        Counter { name, help, value: AtomicU64::new(0) }
    }

    #[inline]
    pub fn inc(&self) {
        self.value.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_by(&self, n: u64) {
        self.value.fetch_add(n, Ordering::Relaxed);
    }

    #[inline]
    pub fn get(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }
}

/// A labeled counter family.  Labels are fixed strings; values are AtomicU64.
/// Uses a sorted slice of (label_value, AtomicU64) for zero-allocation lookup.
pub struct CounterVec {
    pub name:   &'static str,
    pub help:   &'static str,
    pub label:  &'static str,
    pub cells:  Vec<(&'static str, Arc<AtomicU64>)>,
}

impl CounterVec {
    pub fn new(name: &'static str, help: &'static str, label: &'static str, values: &[&'static str]) -> Self {
        let cells = values
            .iter()
            .map(|&v| (v, Arc::new(AtomicU64::new(0))))
            .collect();
        CounterVec { name, help, label, cells }
    }

    pub fn inc(&self, label_value: &str) {
        if let Some((_, c)) = self.cells.iter().find(|(v, _)| *v == label_value) {
            c.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Add `n` to the cell for `label_value` (no-op if the label is unknown).
    pub fn inc_by(&self, label_value: &str, n: u64) {
        if let Some((_, c)) = self.cells.iter().find(|(v, _)| *v == label_value) {
            c.fetch_add(n, Ordering::Relaxed);
        }
    }

    pub fn get(&self, label_value: &str) -> u64 {
        self.cells
            .iter()
            .find(|(v, _)| *v == label_value)
            .map(|(_, c)| c.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&'static str, u64)> + '_ {
        self.cells.iter().map(|(v, c)| (*v, c.load(Ordering::Relaxed)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_increments() {
        let c = Counter::new("test_total", "A test counter");
        assert_eq!(c.get(), 0);
        c.inc();
        c.inc_by(9);
        assert_eq!(c.get(), 10);
    }

    #[test]
    fn counter_vec_by_label() {
        let cv = CounterVec::new("req", "requests", "action", &["allow", "block", "redact"]);
        cv.inc("block");
        cv.inc("block");
        cv.inc("allow");
        assert_eq!(cv.get("block"), 2);
        assert_eq!(cv.get("allow"), 1);
        assert_eq!(cv.get("redact"), 0);
    }
}
