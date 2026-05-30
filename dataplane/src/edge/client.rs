//! Edge gRPC client.
//!
//! The dataplane calls `EdgeClient::invoke()` once per request, after the
//! built-in policy verdict has been decided. The client:
//!
//! 1. Short-circuits when edge is disabled (returns `Unspecified` instantly)
//! 2. Constructs an `EdgeRequest` from the in-flight request
//! 3. Issues a unary gRPC call with a configured timeout
//! 4. Maps the response to the dataplane's `EdgeVerdict` enum, ready for
//!    reconciliation
//!
//! On timeout / unreachable / gRPC error, the client honours
//! `EdgeConfig::fail_open` — returning either `Unspecified` (keep built-in)
//! or `Block` (fail-secure escalation).
//!
//! ## Implementation status
//!
//! This is the **scaffold** — when the `grpc` Cargo feature is OFF (the
//! default until the gRPC dependency lands in `Cargo.toml`), `invoke()`
//! is a no-op that returns `Unspecified` for every call. This keeps the
//! dataplane buildable on the current toolchain (the `tonic` crate has
//! known issues on rustc 1.95.0 — see issue #31) while #28's contract
//! work lands.
//!
//! When the `grpc` feature is wired up, this file gains the real `tonic`
//! channel + the generated `EdgeServiceClient` calls. The public API of
//! `EdgeClient` does NOT change between the two modes — pipeline.rs is
//! agnostic to whether the call is stubbed or real.

use super::config::EdgeConfig;
use super::verdict::EdgeVerdict;

/// Input to the edge call. Constructed by pipeline.rs from the in-flight
/// request + the built-in verdict already decided.
#[derive(Debug, Clone)]
pub struct EdgeInvocation {
    pub workspace_id: String,
    pub request_id: String,
    pub model: String,
    pub prompt: String,
    pub worker_name: String,
    pub current_verdict: EdgeVerdict,
}

/// Output from the edge call. Mirrors the relevant subset of
/// `EdgeResponse` in proto/edge.proto.
#[derive(Debug, Clone)]
pub struct EdgeDecision {
    pub verdict: EdgeVerdict,
    pub reason: String,
    pub worker_latency_ms: f32,
    pub warnings: Vec<String>,
    /// `None` when the worker didn't override the body, `Some(bytes)` when
    /// `has_replacement_body` was true in the gRPC response.
    pub replacement_body: Option<Vec<u8>>,
}

impl EdgeDecision {
    /// A no-op decision — used when edge is disabled or the call short-circuits.
    pub fn unspecified() -> Self {
        Self {
            verdict: EdgeVerdict::Unspecified,
            reason: String::new(),
            worker_latency_ms: 0.0,
            warnings: Vec::new(),
            replacement_body: None,
        }
    }

    /// A fail-secure escalation — used when the call fails and fail_open is false.
    pub fn fail_secure(reason: impl Into<String>) -> Self {
        Self {
            verdict: EdgeVerdict::Block,
            reason: reason.into(),
            worker_latency_ms: 0.0,
            warnings: Vec::new(),
            replacement_body: None,
        }
    }
}

/// The edge gRPC client. Constructed once at dataplane startup and shared
/// across the request pipeline by `Arc`.
pub struct EdgeClient {
    config: EdgeConfig,
    // When the `grpc` feature lands, this holds a tonic channel + a
    // `EdgeServiceClient<Channel>` — for now, just the config so the
    // hot-path short-circuit logic can read `should_invoke`.
}

impl EdgeClient {
    /// Construct the client from environment-derived config. Does NOT
    /// establish a connection — connection is lazy on first call.
    pub fn new(config: EdgeConfig) -> Self {
        Self { config }
    }

    /// Convenience: construct from `std::env`. Used by `main.rs` at startup.
    pub fn from_env() -> Self {
        Self::new(EdgeConfig::from_env())
    }

    /// Whether the edge stage should run for this request. Pipeline.rs
    /// checks this BEFORE constructing an `EdgeInvocation` to avoid the
    /// cost of building the gRPC request struct when edge is off.
    pub fn should_invoke(&self, worker_name: &str) -> bool {
        self.config.should_invoke(worker_name)
    }

    /// Invoke the edge worker. Returns a decision the pipeline can reconcile
    /// against the built-in verdict.
    ///
    /// ## Cancellation / timeout
    ///
    /// The call respects `EdgeConfig::timeout`. On timeout / network error /
    /// gRPC error, returns either `EdgeDecision::unspecified()` (when
    /// `fail_open` is true) or `EdgeDecision::fail_secure(reason)` (when
    /// `fail_open` is false — the default).
    pub fn invoke(&self, _invocation: EdgeInvocation) -> EdgeDecision {
        // Short-circuit when edge is disabled (the hot path)
        if !self.config.enabled {
            return EdgeDecision::unspecified();
        }

        // SCAFFOLD: real gRPC call is gated behind the `grpc` Cargo feature
        // (see dataplane/build.rs). Until the feature lands, returning
        // unspecified preserves the dataplane's pre-#28 behaviour exactly.
        //
        // When the gRPC dependency is wired in, this body becomes:
        //
        //   let req = build_edge_request(&_invocation, &self.config);
        //   match self.tonic_client.run_worker(req).timeout(self.config.timeout).await {
        //       Ok(Ok(resp)) => EdgeDecision::from(resp.into_inner()),
        //       _ if self.config.fail_open => EdgeDecision::unspecified(),
        //       Err(e)       => EdgeDecision::fail_secure(format!("edge call failed: {e}")),
        //       Ok(Err(e))   => EdgeDecision::fail_secure(format!("edge worker errored: {e}")),
        //   }
        EdgeDecision::unspecified()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_invocation() -> EdgeInvocation {
        EdgeInvocation {
            workspace_id: "test".into(),
            request_id: "r_test_01".into(),
            model: "gpt-4o-mini".into(),
            prompt: "hello".into(),
            worker_name: "default-worker".into(),
            current_verdict: EdgeVerdict::Allow,
        }
    }

    #[test]
    fn disabled_client_short_circuits_to_unspecified() {
        let client = EdgeClient::new(EdgeConfig::default());
        let decision = client.invoke(sample_invocation());
        assert_eq!(decision.verdict, EdgeVerdict::Unspecified);
        assert_eq!(decision.replacement_body, None);
    }

    #[test]
    fn should_invoke_respects_config_when_disabled() {
        let client = EdgeClient::new(EdgeConfig::default());
        assert!(!client.should_invoke("any-worker"));
    }

    #[test]
    fn should_invoke_respects_config_when_enabled() {
        let cfg = EdgeConfig {
            enabled: true,
            default_worker: "compliance-v1".into(),
            ..Default::default()
        };
        let client = EdgeClient::new(cfg);
        assert!(client.should_invoke(""), "default worker covers empty request");
        assert!(client.should_invoke("explicit-worker"));
    }

    #[test]
    fn fail_secure_decision_carries_block_verdict() {
        let d = EdgeDecision::fail_secure("simulated timeout");
        assert_eq!(d.verdict, EdgeVerdict::Block);
        assert_eq!(d.reason, "simulated timeout");
    }

    #[test]
    fn unspecified_decision_has_no_replacement_body() {
        let d = EdgeDecision::unspecified();
        assert_eq!(d.verdict, EdgeVerdict::Unspecified);
        assert!(d.replacement_body.is_none());
    }
}
