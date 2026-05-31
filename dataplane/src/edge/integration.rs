//! Edge → pipeline integration glue.
//!
//! This module sits between the dataplane request pipeline and the `EdgeClient`.
//! It provides:
//!
//! 1. A process-global `EdgeClient` (one connection pool per process, lazily
//!    constructed from env on first use).
//! 2. A `reconcile_for_request()` helper the pipeline can call between the
//!    Policy stage and the Respond stage. The helper:
//!       - short-circuits if edge is disabled (the hot path stays microsecond)
//!       - builds the `EdgeInvocation` from in-flight request data
//!       - calls the worker
//!       - reconciles the worker's verdict with the built-in policy verdict
//!       - returns the winning verdict + source attribution for audit
//!
//! Why a separate file from `client.rs`: keeps the gRPC client pure (it knows
//! nothing about the dataplane's `policy::Action` enum). The mapping between
//! `policy::Action` and `EdgeVerdict` lives here, in the integration layer,
//! where the abstraction boundary is correct.

use std::sync::OnceLock;

use super::client::{EdgeClient, EdgeDecision, EdgeInvocation};
use super::verdict::{reconcile, EdgeVerdict, ReconciledVerdict, VerdictSource};

/// Process-global edge client. Initialised lazily from environment on the first
/// `client()` call. Operators that need to swap config at runtime should
/// restart the dataplane — config is read once.
static CLIENT: OnceLock<EdgeClient> = OnceLock::new();

/// Get (or lazily construct) the process-wide edge client.
pub fn client() -> &'static EdgeClient {
    CLIENT.get_or_init(EdgeClient::from_env)
}

/// Inputs the pipeline already has when it reaches the edge stage.
///
/// Kept as a flat struct (rather than borrowing from a pipeline-internal type)
/// so this module stays decoupled from pipeline.rs.
pub struct PipelineContext<'a> {
    pub workspace_id: &'a str,
    pub request_id: &'a str,
    pub model: &'a str,
    pub prompt: &'a str,
    pub worker_name: &'a str,
    pub current_verdict: EdgeVerdict,
    pub allow_de_escalation: bool,
}

/// The result of running the edge stage. The pipeline reads `winner` to drive
/// the Respond stage; reads `source` to write the audit row; reads
/// `worker_latency_ms` and `warnings` to emit Prometheus counters and trace
/// spans.
pub struct EdgeOutcome {
    pub winner: EdgeVerdict,
    pub source: VerdictSource,
    pub worker_latency_ms: f32,
    pub warnings: Vec<String>,
    pub reason: String,
    /// `None` when the worker did not request a body override.
    pub replacement_body: Option<Vec<u8>>,
}

impl EdgeOutcome {
    /// Construct a no-op outcome for the case where edge is disabled or the
    /// pipeline chooses to skip the call.
    pub fn passthrough(current_verdict: EdgeVerdict) -> Self {
        Self {
            winner: current_verdict,
            source: VerdictSource::BuiltIn,
            worker_latency_ms: 0.0,
            warnings: Vec::new(),
            reason: String::new(),
            replacement_body: None,
        }
    }
}

/// Run the edge stage for a single request. The pipeline calls this between
/// the Policy stage and the Respond stage.
///
/// Behaviour:
/// - If the global edge client is disabled, returns
///   `EdgeOutcome::passthrough(current_verdict)` immediately. The hot path is
///   one branch + one allocation.
/// - Otherwise builds the gRPC request, calls the worker, reconciles, returns.
///
/// This function is intentionally synchronous; the real gRPC call inside
/// `EdgeClient::invoke()` is gated behind the `grpc` Cargo feature. Until the
/// feature lands, all paths through this function complete in nanoseconds.
pub fn reconcile_for_request(ctx: &PipelineContext<'_>) -> EdgeOutcome {
    let c = client();

    if !c.should_invoke(ctx.worker_name) {
        return EdgeOutcome::passthrough(ctx.current_verdict);
    }

    let invocation = EdgeInvocation {
        workspace_id: ctx.workspace_id.to_string(),
        request_id: ctx.request_id.to_string(),
        model: ctx.model.to_string(),
        prompt: ctx.prompt.to_string(),
        worker_name: ctx.worker_name.to_string(),
        current_verdict: ctx.current_verdict,
    };

    let decision: EdgeDecision = c.invoke(invocation);

    let reconciled: ReconciledVerdict = reconcile(
        ctx.current_verdict,
        decision.verdict,
        ctx.allow_de_escalation,
    );

    EdgeOutcome {
        winner: reconciled.winner,
        source: reconciled.source,
        worker_latency_ms: decision.worker_latency_ms,
        warnings: decision.warnings,
        reason: decision.reason,
        replacement_body: decision.replacement_body,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx<'a>(current: EdgeVerdict, worker: &'a str) -> PipelineContext<'a> {
        PipelineContext {
            workspace_id: "test-workspace",
            request_id: "r_test_01",
            model: "gpt-4o-mini",
            prompt: "hello world",
            worker_name: worker,
            current_verdict: current,
            allow_de_escalation: false,
        }
    }

    #[test]
    fn passthrough_when_edge_disabled() {
        // The global client picks up env at first call; in the default test
        // environment TSM_EDGE_ENABLED is unset, so the client is disabled
        // and should_invoke returns false regardless of worker name.
        let outcome = reconcile_for_request(&ctx(EdgeVerdict::Redact, "any-worker"));
        assert_eq!(outcome.winner, EdgeVerdict::Redact);
        assert_eq!(outcome.source, VerdictSource::BuiltIn);
        assert!(outcome.replacement_body.is_none());
        assert!(outcome.warnings.is_empty());
    }

    #[test]
    fn passthrough_preserves_block_verdict() {
        let outcome = reconcile_for_request(&ctx(EdgeVerdict::Block, ""));
        assert_eq!(outcome.winner, EdgeVerdict::Block);
        assert_eq!(outcome.source, VerdictSource::BuiltIn);
    }

    #[test]
    fn outcome_passthrough_constructor_works() {
        let outcome = EdgeOutcome::passthrough(EdgeVerdict::Quarantine);
        assert_eq!(outcome.winner, EdgeVerdict::Quarantine);
        assert_eq!(outcome.source, VerdictSource::BuiltIn);
        assert_eq!(outcome.worker_latency_ms, 0.0);
    }
}
