//! Edge — Wasm worker integration on the dataplane request path.
//!
//! This module is the dataplane's gRPC client for the C++ wasmtime edge host
//! (`edge/`). The client is invoked between the Policy stage and the Respond
//! stage of `pipeline.rs`, after the built-in verdict has been decided,
//! giving operator-supplied Wasm workers a chance to extend the policy DSL
//! with "policy as code".
//!
//! ## Reconciliation rule
//!
//! The dataplane takes the more restrictive of (built-in verdict, edge
//! verdict) by severity order:
//!
//! ```text
//!     ALLOW < REDACT < ROUTE_LOCAL < QUARANTINE < BLOCK
//! ```
//!
//! A worker that returns `ALLOW` when the built-in verdict is `BLOCK` does
//! NOT downgrade the verdict unless the workspace has
//! `allow_edge_de_escalation: true` (off by default).
//!
//! ## Fail mode
//!
//! On timeout / unreachable / gRPC error the dataplane consults
//! `TSM_EDGE_FAIL_OPEN`:
//!
//! - `true`  → keep the built-in verdict, log a warning, increment
//!   `tsm_edge_failures_total{reason=…}`
//! - `false` (default) → escalate to `BLOCK`, log the failure, increment the
//!   same counter
//!
//! Fail-secure is the default because the edge worker is part of the
//! policy decision; if the policy oracle is unreachable, the safer default
//! is to refuse.
//!
//! ## Status
//!
//! This is the **client-side scaffold** for issue #28 (Wire dataplane → gRPC
//! + edge on request path). The C++ gRPC server in `edge/src/` is wired in
//! a separate slice. Until the server lands, the client returns
//! `Verdict::Unchanged` for every call when `TSM_EDGE_ENABLED=false` (the
//! default), keeping the dataplane bit-for-bit identical to its pre-#28
//! behaviour.

pub mod client;
pub mod config;
pub mod integration;
pub mod verdict;

pub use client::EdgeClient;
pub use config::EdgeConfig;
pub use integration::{reconcile_for_request, EdgeOutcome, PipelineContext};
pub use verdict::{EdgeVerdict, ReconciledVerdict};
