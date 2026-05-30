//! Edge verdict reconciliation.
//!
//! The five-verdict taxonomy is shared between the dataplane's built-in
//! policy engine and the edge worker. After the worker returns its verdict,
//! the dataplane reconciles the two by severity order:
//!
//! ```text
//!     ALLOW < REDACT < ROUTE_LOCAL < QUARANTINE < BLOCK
//! ```
//!
//! The MORE RESTRICTIVE verdict wins — unless the workspace permits
//! de-escalation (off by default).

use std::cmp::Ordering;

/// The edge verdict, mirroring `proto.tsm.edge.EdgeVerdict`. Kept as a Rust
/// enum so the rest of the dataplane can pattern-match without depending on
/// the generated `prost` types directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeVerdict {
    Unspecified,
    Allow,
    Redact,
    RouteLocal,
    Quarantine,
    Block,
}

impl EdgeVerdict {
    /// Severity rank — higher means more restrictive. Used for reconciliation.
    fn severity_rank(self) -> u8 {
        match self {
            Self::Unspecified => 0, // never wins reconciliation
            Self::Allow => 1,
            Self::Redact => 2,
            Self::RouteLocal => 3,
            Self::Quarantine => 4,
            Self::Block => 5,
        }
    }
}

impl PartialOrd for EdgeVerdict {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for EdgeVerdict {
    fn cmp(&self, other: &Self) -> Ordering {
        self.severity_rank().cmp(&other.severity_rank())
    }
}

/// The outcome of reconciling (built-in verdict, edge verdict).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReconciledVerdict {
    pub winner: EdgeVerdict,
    pub source: VerdictSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerdictSource {
    /// Built-in policy alone — edge stage was skipped or returned Unspecified.
    BuiltIn,
    /// Edge worker upgraded the built-in verdict to something more restrictive.
    EdgeEscalation,
    /// Edge worker explicitly de-escalated (only allowed when the workspace
    /// has `allow_edge_de_escalation: true`).
    EdgeDeEscalation,
}

/// Reconcile a built-in policy verdict with an edge worker verdict. By
/// default, the MORE restrictive verdict wins. De-escalation is only
/// permitted when `allow_de_escalation` is true.
pub fn reconcile(
    built_in: EdgeVerdict,
    edge: EdgeVerdict,
    allow_de_escalation: bool,
) -> ReconciledVerdict {
    // Worker returned Unspecified — treat as "no opinion", keep built-in.
    if edge == EdgeVerdict::Unspecified {
        return ReconciledVerdict {
            winner: built_in,
            source: VerdictSource::BuiltIn,
        };
    }

    match edge.cmp(&built_in) {
        Ordering::Greater => ReconciledVerdict {
            winner: edge,
            source: VerdictSource::EdgeEscalation,
        },
        Ordering::Less if allow_de_escalation => ReconciledVerdict {
            winner: edge,
            source: VerdictSource::EdgeDeEscalation,
        },
        // Edge tried to de-escalate but workspace forbids — keep built-in.
        Ordering::Less => ReconciledVerdict {
            winner: built_in,
            source: VerdictSource::BuiltIn,
        },
        Ordering::Equal => ReconciledVerdict {
            winner: built_in,
            source: VerdictSource::BuiltIn,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_order_is_correct() {
        assert!(EdgeVerdict::Allow < EdgeVerdict::Redact);
        assert!(EdgeVerdict::Redact < EdgeVerdict::RouteLocal);
        assert!(EdgeVerdict::RouteLocal < EdgeVerdict::Quarantine);
        assert!(EdgeVerdict::Quarantine < EdgeVerdict::Block);
    }

    #[test]
    fn edge_escalation_wins() {
        let r = reconcile(EdgeVerdict::Allow, EdgeVerdict::Block, false);
        assert_eq!(r.winner, EdgeVerdict::Block);
        assert_eq!(r.source, VerdictSource::EdgeEscalation);
    }

    #[test]
    fn edge_de_escalation_blocked_by_default() {
        let r = reconcile(EdgeVerdict::Block, EdgeVerdict::Allow, false);
        assert_eq!(r.winner, EdgeVerdict::Block, "must keep built-in BLOCK");
        assert_eq!(r.source, VerdictSource::BuiltIn);
    }

    #[test]
    fn edge_de_escalation_permitted_when_workspace_allows() {
        let r = reconcile(EdgeVerdict::Block, EdgeVerdict::Allow, true);
        assert_eq!(r.winner, EdgeVerdict::Allow);
        assert_eq!(r.source, VerdictSource::EdgeDeEscalation);
    }

    #[test]
    fn equal_verdicts_keep_built_in_source() {
        let r = reconcile(EdgeVerdict::Redact, EdgeVerdict::Redact, false);
        assert_eq!(r.winner, EdgeVerdict::Redact);
        assert_eq!(r.source, VerdictSource::BuiltIn);
    }

    #[test]
    fn edge_unspecified_keeps_built_in() {
        let r = reconcile(EdgeVerdict::RouteLocal, EdgeVerdict::Unspecified, false);
        assert_eq!(r.winner, EdgeVerdict::RouteLocal);
        assert_eq!(r.source, VerdictSource::BuiltIn);
    }
}
