//! Edge configuration — env-driven, hot-readable.
//!
//! All edge config is sourced from environment variables so operators can
//! flip behaviour without rebuilding the dataplane. The config is read once
//! at startup and cached.

use std::env;
use std::time::Duration;

/// Runtime configuration for the edge client.
///
/// Constructed once at dataplane startup from the environment.
#[derive(Debug, Clone)]
pub struct EdgeConfig {
    /// Master switch. When `false`, the edge stage is a no-op — the dataplane
    /// behaves bit-for-bit as it did before #28 landed.
    pub enabled: bool,

    /// gRPC endpoint of the edge host. E.g. `http://edge-host:50052`.
    /// Ignored when `enabled` is false.
    pub endpoint: String,

    /// Per-call timeout for the worker invocation. Workers that exceed this
    /// are treated as failed (see `fail_open`).
    pub timeout: Duration,

    /// Fail mode. `false` (default) escalates failures to BLOCK; `true` keeps
    /// the built-in verdict on failure.
    pub fail_open: bool,

    /// Default worker name to invoke when the workspace policy doesn't
    /// specify one. Empty string means "no default — skip edge call".
    pub default_worker: String,
}

impl EdgeConfig {
    /// Read config from environment. Called once at dataplane startup.
    pub fn from_env() -> Self {
        Self {
            enabled: env_bool("TSM_EDGE_ENABLED", false),
            endpoint: env::var("TSM_EDGE_ENDPOINT")
                .unwrap_or_else(|_| "http://localhost:50052".to_string()),
            timeout: Duration::from_millis(env_u64("TSM_EDGE_TIMEOUT_MS", 50)),
            fail_open: env_bool("TSM_EDGE_FAIL_OPEN", false),
            default_worker: env::var("TSM_EDGE_DEFAULT_WORKER").unwrap_or_default(),
        }
    }

    /// True when the edge stage should run for a given request. The dataplane
    /// calls this before constructing the gRPC request — short-circuits the
    /// hot path when the edge is off.
    pub fn should_invoke(&self, worker_name: &str) -> bool {
        if !self.enabled {
            return false;
        }
        // If the request didn't specify a worker AND there's no default,
        // skip the edge call entirely.
        !worker_name.is_empty() || !self.default_worker.is_empty()
    }
}

impl Default for EdgeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: "http://localhost:50052".to_string(),
            timeout: Duration::from_millis(50),
            fail_open: false,
            default_worker: String::new(),
        }
    }
}

fn env_bool(key: &str, default: bool) -> bool {
    match env::var(key).ok().as_deref() {
        Some("1" | "true" | "TRUE" | "yes" | "YES") => true,
        Some("0" | "false" | "FALSE" | "no" | "NO" | "") | None => default,
        Some(_) => default,
    }
}

fn env_u64(key: &str, default: u64) -> u64 {
    env::var(key)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_disabled() {
        let cfg = EdgeConfig::default();
        assert!(!cfg.enabled);
        assert!(!cfg.fail_open, "fail-secure must be the default");
        assert_eq!(cfg.timeout, Duration::from_millis(50));
    }

    #[test]
    fn should_invoke_short_circuits_when_disabled() {
        let cfg = EdgeConfig::default();
        assert!(!cfg.should_invoke("some-worker"));
        assert!(!cfg.should_invoke(""));
    }

    #[test]
    fn should_invoke_requires_a_worker_when_enabled() {
        let cfg = EdgeConfig {
            enabled: true,
            default_worker: String::new(),
            ..Default::default()
        };
        assert!(!cfg.should_invoke(""), "no worker name + no default ⇒ skip");
        assert!(cfg.should_invoke("custom-worker"));
    }

    #[test]
    fn should_invoke_uses_default_worker() {
        let cfg = EdgeConfig {
            enabled: true,
            default_worker: "compliance-v1".to_string(),
            ..Default::default()
        };
        assert!(cfg.should_invoke(""), "empty request worker falls back to default");
    }
}
