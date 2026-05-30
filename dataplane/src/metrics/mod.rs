pub mod counters;
pub mod histogram;
pub mod prometheus;

pub use counters::{Counter, CounterVec};
pub use histogram::{Histogram, LATENCY_BOUNDS_MS, DETECTOR_BOUNDS_MS};

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use serde_json::Value;

// ── Recent-request ring buffer ────────────────────────────────────────────────

const RING_CAPACITY: usize = 20;

#[derive(Clone, serde::Serialize)]
pub struct RecentRequest {
    pub request_id:  String,
    pub org_id:      String,
    pub model:       String,
    pub action:      String,
    pub risk_score:  f64,
    pub pii_types:   Vec<String>,
    pub latency_ms:  f64,
    pub timestamp:   u64,   // Unix seconds
}

// ── Metrics store ─────────────────────────────────────────────────────────────

pub struct MetricsStore {
    // Counters — labeled
    pub requests_by_action: CounterVec,   // label: action  (allow|block|redact|route_local)
    pub fastpath_hits:      CounterVec,   // label: pii_type
    pub circuit_open:       CounterVec,   // label: upstream
    pub pii_types:          CounterVec,   // label: pii_type
    pub tokens_prompt:      CounterVec,   // label: provider — exact input tokens (from upstream usage)
    pub tokens_completion:  CounterVec,   // label: provider — exact output tokens (from upstream usage)

    // Counters — scalar
    pub detector_calls:     Counter,
    pub rate_limited:       Counter,
    pub pool_connections:   Counter,

    // Histograms — per action
    pub latency_allow:       Histogram,
    pub latency_block:       Histogram,
    pub latency_redact:      Histogram,
    pub latency_route_local: Histogram,

    // Histogram — detector
    pub latency_detector:    Histogram,

    // Risk score running average (stored as micro-units to avoid floats in atomics)
    risk_sum_micro: AtomicU64,   // sum of (risk_score * 1_000_000) as u64
    risk_count:     AtomicU64,

    // Recent requests ring buffer
    recent: Mutex<VecDeque<RecentRequest>>,
}

impl MetricsStore {
    fn new() -> Self {
        // All known PII types for the labeled counter families.
        // These match the detector + fast-path pattern names.
        const PII_TYPES: &[&str] = &[
            "SSN", "CREDIT_CARD", "EMAIL", "PHONE", "IP_ADDRESS",
            "OPENAI_KEY", "ANTHROPIC_KEY", "AWS_KEY", "GITHUB_TOKEN",
            "SENDGRID_KEY", "HUGGINGFACE_KEY", "GITLAB_TOKEN",
            "JWT", "HIGH_ENTROPY", "JAILBREAK",
        ];
        const UPSTREAMS: &[&str] = &["openai", "anthropic", "ollama", "local"];
        const PROVIDERS: &[&str] = &["openai", "anthropic", "ollama", "local", "unknown"];
        const ACTIONS:   &[&str] = &["allow", "block", "redact", "route_local"];

        MetricsStore {
            requests_by_action: CounterVec::new(
                "tsm_requests_total", "Total requests by action", "action", ACTIONS,
            ),
            fastpath_hits: CounterVec::new(
                "tsm_fastpath_hits_total", "Fast-path hits by PII type", "pii_type", PII_TYPES,
            ),
            circuit_open: CounterVec::new(
                "tsm_circuit_open_total", "Requests rejected by open circuit breaker", "upstream", UPSTREAMS,
            ),
            pii_types: CounterVec::new(
                "tsm_pii_types_detected_total", "PII types detected", "pii_type", PII_TYPES,
            ),
            tokens_prompt: CounterVec::new(
                "tsm_tokens_prompt_total", "Prompt (input) tokens by provider", "provider", PROVIDERS,
            ),
            tokens_completion: CounterVec::new(
                "tsm_tokens_completion_total", "Completion (output) tokens by provider", "provider", PROVIDERS,
            ),

            detector_calls:   Counter::new("tsm_detector_calls_total",   "Calls to the Python detector"),
            rate_limited:     Counter::new("tsm_rate_limited_total",      "Requests rejected by rate limiter"),
            pool_connections: Counter::new("tsm_pool_connections_total",  "TLS connections established to upstreams"),

            latency_allow:       Histogram::new("tsm_request_duration_ms_allow",       "allow latency ms",       LATENCY_BOUNDS_MS),
            latency_block:       Histogram::new("tsm_request_duration_ms_block",       "block latency ms",       LATENCY_BOUNDS_MS),
            latency_redact:      Histogram::new("tsm_request_duration_ms_redact",      "redact latency ms",      LATENCY_BOUNDS_MS),
            latency_route_local: Histogram::new("tsm_request_duration_ms_route_local", "route_local latency ms", LATENCY_BOUNDS_MS),
            latency_detector:    Histogram::new("tsm_detector_duration_ms",            "detector latency ms",    DETECTOR_BOUNDS_MS),

            risk_sum_micro: AtomicU64::new(0),
            risk_count:     AtomicU64::new(0),

            recent: Mutex::new(VecDeque::with_capacity(RING_CAPACITY + 1)),
        }
    }

    // ── Recording helpers ─────────────────────────────────────────────────────

    /// Record a completed request: action, latency, risk score, PII types hit.
    pub fn record_request(
        &self,
        action:     &str,
        latency_ms: f64,
        risk_score: f64,
        pii_types:  &[String],
        req:        RecentRequest,
    ) {
        self.requests_by_action.inc(action);

        match action {
            "allow"       => self.latency_allow.observe(latency_ms),
            "block"       => self.latency_block.observe(latency_ms),
            "redact"      => self.latency_redact.observe(latency_ms),
            "route_local" => self.latency_route_local.observe(latency_ms),
            _             => {}
        }

        // Update running risk average (risk stored as micro-units)
        self.risk_sum_micro.fetch_add((risk_score * 1_000_000.0) as u64, Ordering::Relaxed);
        self.risk_count.fetch_add(1, Ordering::Relaxed);

        // Increment per-pii-type counters
        for pt in pii_types {
            self.pii_types.inc(pt);
        }

        // Append to ring buffer, evict oldest if full
        if let Ok(mut ring) = self.recent.lock() {
            ring.push_back(req);
            if ring.len() > RING_CAPACITY {
                ring.pop_front();
            }
        }
    }

    /// Record a fast-path hit by PII type (before full detection pipeline).
    pub fn record_fastpath_hit(&self, pii_type: &str) {
        self.fastpath_hits.inc(pii_type);
    }

    /// Record a detector HTTP call and its latency.
    pub fn record_detector_call(&self, latency_ms: f64) {
        self.detector_calls.inc();
        self.latency_detector.observe(latency_ms);
    }

    /// Record a rate-limited request.
    pub fn record_rate_limited(&self) {
        self.rate_limited.inc();
    }

    /// Record a circuit-open rejection for a given upstream.
    pub fn record_circuit_open(&self, upstream: &str) {
        self.circuit_open.inc(upstream);
    }

    /// Record a new upstream TLS connection.
    pub fn record_pool_connection(&self) {
        self.pool_connections.inc();
    }

    /// Record exact token usage (from the upstream `usage` field) by provider.
    /// Powers cross-provider cost tracking. `provider` is normalised to a known
    /// label (falls back to "unknown") so no usage is silently dropped.
    pub fn record_usage(&self, provider: &str, prompt_tokens: u64, completion_tokens: u64) {
        let known = ["openai", "anthropic", "ollama", "local"];
        let label = if known.contains(&provider) { provider } else { "unknown" };
        self.tokens_prompt.inc_by(label, prompt_tokens);
        self.tokens_completion.inc_by(label, completion_tokens);
    }

    // ── Query helpers ─────────────────────────────────────────────────────────

    /// Exponential moving average of risk scores (0.0 if no requests yet).
    pub fn avg_risk_score(&self) -> f64 {
        let count = self.risk_count.load(Ordering::Relaxed);
        if count == 0 {
            return 0.0;
        }
        let sum_micro = self.risk_sum_micro.load(Ordering::Relaxed);
        (sum_micro as f64 / 1_000_000.0) / count as f64
    }

    /// Snapshot of the most recent requests as a JSON array.
    pub fn recent_requests(&self) -> Value {
        match self.recent.lock() {
            Ok(ring) => {
                let entries: Vec<Value> = ring
                    .iter()
                    .map(|r| serde_json::json!({
                        "request_id": r.request_id,
                        "org_id":     r.org_id,
                        "model":      r.model,
                        "action":     r.action,
                        "risk_score": r.risk_score,
                        "pii_types":  r.pii_types,
                        "latency_ms": r.latency_ms,
                        "timestamp":  r.timestamp,
                    }))
                    .collect();
                Value::Array(entries)
            }
            Err(_) => Value::Array(vec![]),
        }
    }

    /// How many slots the recent-requests ring holds.
    pub fn ring_size(&self) -> usize {
        RING_CAPACITY
    }
}

// ── Global singleton ──────────────────────────────────────────────────────────

static METRICS_CELL: OnceLock<MetricsStore> = OnceLock::new();

/// Return a reference to the process-wide `MetricsStore`, initialising it on
/// first call.  All subsequent calls return the same reference.
pub fn metrics() -> &'static MetricsStore {
    METRICS_CELL.get_or_init(MetricsStore::new)
}

// The prometheus module accesses metrics via `METRICS` which is declared as:
//   use super::{METRICS, MetricsStore};
// We satisfy this by providing a pub static reference wrapper.
pub static METRICS: MetricsStoreRef = MetricsStoreRef;

pub struct MetricsStoreRef;

impl std::ops::Deref for MetricsStoreRef {
    type Target = MetricsStore;
    fn deref(&self) -> &MetricsStore {
        metrics()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_store() -> MetricsStore {
        MetricsStore::new()
    }

    #[test]
    fn record_request_increments_action_counter() {
        let s = fresh_store();
        let req = RecentRequest {
            request_id: "r1".into(), org_id: "o1".into(), model: "gpt-4".into(),
            action: "block".into(), risk_score: 95.0, pii_types: vec!["SSN".into()],
            latency_ms: 12.5, timestamp: 0,
        };
        s.record_request("block", 12.5, 95.0, &["SSN".to_string()], req);
        assert_eq!(s.requests_by_action.get("block"), 1);
        assert_eq!(s.requests_by_action.get("allow"), 0);
    }

    #[test]
    fn avg_risk_score_correct() {
        let s = fresh_store();
        for score in [10.0_f64, 50.0, 90.0] {
            let req = RecentRequest {
                request_id: "x".into(), org_id: "o".into(), model: "m".into(),
                action: "allow".into(), risk_score: score, pii_types: vec![],
                latency_ms: 1.0, timestamp: 0,
            };
            s.record_request("allow", 1.0, score, &[], req);
        }
        let avg = s.avg_risk_score();
        assert!((avg - 50.0).abs() < 0.001, "Expected avg ~50, got {}", avg);
    }

    #[test]
    fn ring_buffer_evicts_oldest() {
        let s = fresh_store();
        for i in 0..=RING_CAPACITY {
            let req = RecentRequest {
                request_id: format!("r{}", i),
                org_id: "o".into(), model: "m".into(), action: "allow".into(),
                risk_score: 0.0, pii_types: vec![], latency_ms: 1.0, timestamp: i as u64,
            };
            s.record_request("allow", 1.0, 0.0, &[], req);
        }
        let ring = s.recent.lock().unwrap();
        assert_eq!(ring.len(), RING_CAPACITY);
        // The oldest entry (r0) should have been evicted; r1 is now first
        assert_eq!(ring.front().unwrap().request_id, "r1");
    }

    #[test]
    fn pii_type_counter_incremented() {
        let s = fresh_store();
        let req = RecentRequest {
            request_id: "r".into(), org_id: "o".into(), model: "m".into(),
            action: "block".into(), risk_score: 99.0,
            pii_types: vec!["SSN".into(), "EMAIL".into()],
            latency_ms: 5.0, timestamp: 0,
        };
        s.record_request("block", 5.0, 99.0, &["SSN".to_string(), "EMAIL".to_string()], req);
        assert_eq!(s.pii_types.get("SSN"),   1);
        assert_eq!(s.pii_types.get("EMAIL"), 1);
        assert_eq!(s.pii_types.get("PHONE"), 0);
    }
}
