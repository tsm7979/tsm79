/// Circuit breaker for upstream AI provider connections.
///
/// Three-state FSM:
///   Closed    → normal operation; failures increment counter.
///   Open      → upstream declared failed; all requests rejected immediately
///               for OPEN_TIMEOUT before transitioning to Half-Open.
///   Half-Open → probe mode; one request allowed through per PROBE_INTERVAL.
///               success → Closed; failure → back to Open.
///
/// Configuration (hard-coded, reasonable defaults):
///   FAILURE_THRESHOLD = 5   consecutive failures to trip
///   SUCCESS_THRESHOLD = 2   consecutive successes to close from half-open
///   OPEN_TIMEOUT      = 30s before entering half-open
///   PROBE_INTERVAL    = 5s  between half-open probe attempts
///
/// Thread-safe: all state behind a single Mutex.

use std::sync::Mutex;
use std::time::{Duration, Instant};

// ── Config ────────────────────────────────────────────────────────────────────

const FAILURE_THRESHOLD: u32     = 5;
const SUCCESS_THRESHOLD: u32     = 2;
const OPEN_TIMEOUT:      Duration = Duration::from_secs(30);
const PROBE_INTERVAL:    Duration = Duration::from_secs(5);

// ── State machine ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
enum State {
    /// Normal operation.
    Closed { consecutive_failures: u32 },
    /// Upstream declared failed; reject without attempting.
    Open { tripped_at: Instant },
    /// Probe phase: allow one request at a time.
    HalfOpen {
        consecutive_successes: u32,
        last_probe:            Instant,
        probe_in_flight:       bool,
    },
}

impl State {
    fn name(&self) -> &'static str {
        match self {
            State::Closed { .. }   => "closed",
            State::Open { .. }     => "open",
            State::HalfOpen { .. } => "half-open",
        }
    }
}

// ── Public types ──────────────────────────────────────────────────────────────

/// Result of `CircuitBreaker::check()`.
#[derive(Debug, PartialEq)]
pub enum CircuitDecision {
    /// Request may proceed.
    Allow,
    /// Circuit is open; reject immediately without hitting the upstream.
    Reject { reason: &'static str },
}

/// Outcome to feed back via `CircuitBreaker::record()`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Outcome {
    Success,
    Failure,
}

// ── CircuitBreaker ────────────────────────────────────────────────────────────

pub struct CircuitBreaker {
    name:  &'static str,
    inner: Mutex<State>,
}

impl CircuitBreaker {
    pub fn new(name: &'static str) -> Self {
        CircuitBreaker {
            name,
            inner: Mutex::new(State::Closed { consecutive_failures: 0 }),
        }
    }

    /// Check whether the circuit allows a request right now.
    pub fn check(&self) -> CircuitDecision {
        let mut state = self.inner.lock().unwrap();
        let now = Instant::now();

        match &*state {
            State::Closed { .. } => CircuitDecision::Allow,

            State::Open { tripped_at } => {
                if now.duration_since(*tripped_at) >= OPEN_TIMEOUT {
                    // Transition to Half-Open.
                    *state = State::HalfOpen {
                        consecutive_successes: 0,
                        last_probe:            now,
                        probe_in_flight:       true,
                    };
                    eprintln!("[circuit:{}] → half-open (probe allowed)", self.name);
                    CircuitDecision::Allow
                } else {
                    CircuitDecision::Reject { reason: "circuit open" }
                }
            }

            State::HalfOpen { probe_in_flight, last_probe, consecutive_successes } => {
                if *probe_in_flight {
                    // Probe already in flight; reject additional requests.
                    CircuitDecision::Reject { reason: "half-open probe in flight" }
                } else if now.duration_since(*last_probe) >= PROBE_INTERVAL {
                    // Time for a new probe.
                    *state = State::HalfOpen {
                        consecutive_successes: *consecutive_successes,
                        last_probe:            now,
                        probe_in_flight:       true,
                    };
                    CircuitDecision::Allow
                } else {
                    CircuitDecision::Reject { reason: "half-open cooldown" }
                }
            }
        }
    }

    /// Record the outcome of a request that was allowed through.
    pub fn record(&self, outcome: Outcome) {
        let mut state = self.inner.lock().unwrap();
        let now = Instant::now();

        match (&*state, outcome) {
            // ── Closed + success → reset counter ──────────────────────────────
            (State::Closed { .. }, Outcome::Success) => {
                *state = State::Closed { consecutive_failures: 0 };
            }

            // ── Closed + failure → increment, maybe trip ───────────────────
            (State::Closed { consecutive_failures }, Outcome::Failure) => {
                let new_count = consecutive_failures + 1;
                if new_count >= FAILURE_THRESHOLD {
                    eprintln!(
                        "[circuit:{}] OPEN — {} consecutive failures",
                        self.name, new_count
                    );
                    *state = State::Open { tripped_at: now };
                } else {
                    *state = State::Closed { consecutive_failures: new_count };
                }
            }

            // ── Half-open + success → maybe close ─────────────────────────
            (State::HalfOpen { consecutive_successes, .. }, Outcome::Success) => {
                let new_successes = consecutive_successes + 1;
                if new_successes >= SUCCESS_THRESHOLD {
                    eprintln!("[circuit:{}] → closed (recovered)", self.name);
                    *state = State::Closed { consecutive_failures: 0 };
                } else {
                    *state = State::HalfOpen {
                        consecutive_successes: new_successes,
                        last_probe:            now,
                        probe_in_flight:       false,
                    };
                }
            }

            // ── Half-open + failure → re-open ──────────────────────────────
            (State::HalfOpen { .. }, Outcome::Failure) => {
                eprintln!("[circuit:{}] → open (probe failed)", self.name);
                *state = State::Open { tripped_at: now };
            }

            // ── Open outcomes (shouldn't happen — log and ignore) ──────────
            (State::Open { .. }, _) => {
                eprintln!("[circuit:{}] WARN: record() called while open", self.name);
            }
        }
    }

    /// Current state name for /health reporting.
    pub fn state_name(&self) -> &'static str {
        self.inner.lock().unwrap().name()
    }

    /// True if the circuit is closed (healthy).
    pub fn is_healthy(&self) -> bool {
        matches!(*self.inner.lock().unwrap(), State::Closed { .. })
    }
}

// ── Convenience macro ─────────────────────────────────────────────────────────

/// Wrap a fallible expression with circuit-breaker check + record.
///
/// Usage:
/// ```ignore
/// let result = with_circuit!(breaker, { upstream_call() });
/// ```
/// Returns Err("circuit open") if rejected, otherwise the inner Result.
#[macro_export]
macro_rules! with_circuit {
    ($cb:expr, $expr:expr) => {{
        use $crate::pool::circuit::{CircuitDecision, Outcome};
        match $cb.check() {
            CircuitDecision::Allow => {
                let r = $expr;
                $cb.record(if r.is_ok() { Outcome::Success } else { Outcome::Failure });
                r.map_err(|e| e.to_string())
            }
            CircuitDecision::Reject { reason } => {
                Err(format!("circuit breaker: {}", reason))
            }
        }
    }};
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_closed_allows_requests() {
        let cb = CircuitBreaker::new("test");
        assert_eq!(cb.check(), CircuitDecision::Allow);
        assert_eq!(cb.state_name(), "closed");
    }

    #[test]
    fn trips_after_failure_threshold() {
        let cb = CircuitBreaker::new("test");
        for _ in 0..FAILURE_THRESHOLD {
            cb.check();
            cb.record(Outcome::Failure);
        }
        assert_eq!(cb.state_name(), "open");
        assert_eq!(
            cb.check(),
            CircuitDecision::Reject { reason: "circuit open" }
        );
    }

    #[test]
    fn success_resets_failure_counter() {
        let cb = CircuitBreaker::new("test");
        for _ in 0..(FAILURE_THRESHOLD - 1) {
            cb.check();
            cb.record(Outcome::Failure);
        }
        // One success should reset.
        cb.check();
        cb.record(Outcome::Success);
        // Need FAILURE_THRESHOLD more failures to trip again.
        for _ in 0..(FAILURE_THRESHOLD - 1) {
            cb.check();
            cb.record(Outcome::Failure);
        }
        assert_eq!(cb.state_name(), "closed");
    }

    #[test]
    fn half_open_probe_success_closes() {
        let cb = CircuitBreaker::new("test");
        // Force open.
        for _ in 0..FAILURE_THRESHOLD {
            cb.check();
            cb.record(Outcome::Failure);
        }
        // Manually set tripped_at to past so timeout passes.
        {
            let mut state = cb.inner.lock().unwrap();
            *state = State::Open {
                tripped_at: Instant::now()
                    .checked_sub(OPEN_TIMEOUT + Duration::from_secs(1))
                    .unwrap_or(Instant::now()),
            };
        }
        // check() should allow (→ half-open).
        assert_eq!(cb.check(), CircuitDecision::Allow);
        assert_eq!(cb.state_name(), "half-open");
        // SUCCESS_THRESHOLD successes → closed.
        for _ in 0..SUCCESS_THRESHOLD {
            cb.record(Outcome::Success);
        }
        assert_eq!(cb.state_name(), "closed");
    }

    #[test]
    fn half_open_probe_failure_reopens() {
        let cb = CircuitBreaker::new("test");
        for _ in 0..FAILURE_THRESHOLD {
            cb.check();
            cb.record(Outcome::Failure);
        }
        {
            let mut state = cb.inner.lock().unwrap();
            *state = State::Open {
                tripped_at: Instant::now()
                    .checked_sub(OPEN_TIMEOUT + Duration::from_secs(1))
                    .unwrap_or(Instant::now()),
            };
        }
        cb.check(); // → half-open, probe in flight
        cb.record(Outcome::Failure); // → open again
        assert_eq!(cb.state_name(), "open");
    }

    #[test]
    fn concurrent_half_open_blocked() {
        let cb = CircuitBreaker::new("test");
        // Manually set to half-open with probe in flight.
        {
            let mut state = cb.inner.lock().unwrap();
            *state = State::HalfOpen {
                consecutive_successes: 0,
                last_probe:            Instant::now(),
                probe_in_flight:       true,
            };
        }
        assert_eq!(
            cb.check(),
            CircuitDecision::Reject { reason: "half-open probe in flight" }
        );
    }
}
