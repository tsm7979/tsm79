/// Policy rule types: conditions and actions.
///
/// A `PolicyRule` maps a set of conditions to an action.
/// Rules are evaluated in ascending priority order; the first match wins.

use std::collections::HashMap;

// ── Action ────────────────────────────────────────────────────────────────────

/// What to do when a rule matches.
#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    /// Allow the request to proceed to the upstream.
    Allow,
    /// Block the request; return a 400 error to the client.
    Block { reason: String },
    /// Strip PII from the request body before forwarding.
    Redact,
    /// Forward to the local/on-prem model instead of the cloud upstream.
    RouteLocal,
    /// Hold the request for manual review — do NOT forward to any model and do
    /// NOT hard-reject. The client receives a "held for review" (202) response
    /// and the event is audited as `quarantine`. Distinct from `Block` (which
    /// rejects with 400): quarantine ISOLATES suspicious-but-unresolved content
    /// for a human/async decision. Completes the PDF verdict taxonomy
    /// (allow / redact / route / block / quarantine).
    Quarantine { reason: String },
    /// Send to the Python detector for deep NER analysis.
    RequireDetector,
    /// Add extra audit metadata without changing the routing decision.
    AuditAndContinue { tags: Vec<String> },
}

// ── Condition ─────────────────────────────────────────────────────────────────

/// A single condition that can be tested against an `EvalContext`.
#[derive(Debug, Clone)]
pub enum Condition {
    /// The detected PII types include at least one from this set.
    AnyOf { pii_types: Vec<String> },
    /// The detected PII types include ALL of these types.
    AllOf { pii_types: Vec<String> },
    /// Risk score is greater than or equal to the given value.
    RiskScoreGte { threshold: f64 },
    /// Risk score is strictly less than the given value.
    RiskScoreLt { threshold: f64 },
    /// The composite severity label matches exactly.
    SeverityIs { severity: String },
    /// The model name starts with the given prefix (case-insensitive).
    ModelPrefix { prefix: String },
    /// The org ID matches exactly.
    OrgId { org_id: String },
    /// A metadata key equals a specific value.
    Metadata { key: String, value: String },
    /// Logical AND of sub-conditions.
    And { conditions: Vec<Condition> },
    /// Logical OR of sub-conditions.
    Or { conditions: Vec<Condition> },
    /// Logical NOT of a sub-condition.
    Not { condition: Box<Condition> },
    /// Always true — used as the default/catch-all rule.
    Always,
}

impl Condition {
    /// Evaluate this condition against the provided context.
    pub fn evaluate(&self, ctx: &EvalContext) -> bool {
        match self {
            Condition::AnyOf { pii_types } => {
                pii_types.iter().any(|t| ctx.pii_types.contains(t))
            }
            Condition::AllOf { pii_types } => {
                pii_types.iter().all(|t| ctx.pii_types.contains(t))
            }
            Condition::RiskScoreGte { threshold } => ctx.risk_score >= *threshold,
            Condition::RiskScoreLt  { threshold } => ctx.risk_score <  *threshold,
            Condition::SeverityIs   { severity  } => ctx.severity == *severity,
            Condition::ModelPrefix  { prefix    } => {
                ctx.model.to_lowercase().starts_with(&prefix.to_lowercase())
            }
            Condition::OrgId { org_id } => ctx.org_id == *org_id,
            Condition::Metadata { key, value } => {
                ctx.metadata.get(key).map(|v| v == value).unwrap_or(false)
            }
            Condition::And { conditions } => conditions.iter().all(|c| c.evaluate(ctx)),
            Condition::Or  { conditions } => conditions.iter().any(|c| c.evaluate(ctx)),
            Condition::Not { condition  } => !condition.evaluate(ctx),
            Condition::Always           => true,
        }
    }
}

// ── Evaluation context ────────────────────────────────────────────────────────

/// Context passed to the policy engine for each request.
#[derive(Debug, Clone)]
pub struct EvalContext {
    /// PII types detected by the fast-path scanner (e.g. `["SSN", "EMAIL"]`).
    pub pii_types:  Vec<String>,
    /// Composite risk score 0–100.
    pub risk_score: f64,
    /// Severity string: "none" | "low" | "medium" | "high" | "critical".
    pub severity:   String,
    /// AI model name from the request (e.g. `"gpt-4o"`).
    pub model:      String,
    /// Org ID from the request header.
    pub org_id:     String,
    /// Arbitrary metadata key-value pairs (from request headers or body).
    pub metadata:   HashMap<String, String>,
}

// ── Policy rule ───────────────────────────────────────────────────────────────

/// A named policy rule.
#[derive(Debug, Clone)]
pub struct PolicyRule {
    /// Unique name for this rule (used for logging and removal).
    pub name:      String,
    /// Lower value = higher priority; first matching rule wins.
    pub priority:  i32,
    /// Whether this rule is currently active.
    pub enabled:   bool,
    /// The condition that must be true for this rule to fire.
    pub condition: Condition,
    /// The action to take when the condition is satisfied.
    pub action:    Action,
}

impl PolicyRule {
    pub fn new(name: &str, priority: i32, condition: Condition, action: Action) -> Self {
        PolicyRule {
            name:      name.to_owned(),
            priority,
            enabled:   true,
            condition,
            action,
        }
    }

    /// Builder helper for setting `enabled` flag (used by hot-reload).
    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }
}

// ── Policy result ─────────────────────────────────────────────────────────────

/// The result of evaluating the policy engine against a context.
#[derive(Debug, Clone)]
pub struct PolicyResult {
    /// The action determined by the first matching rule.
    pub action:    Action,
    /// The name of the rule that matched (for audit logging).
    pub rule_name: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(risk: f64, pii: &[&str], sev: &str) -> EvalContext {
        EvalContext {
            pii_types:  pii.iter().map(|s| s.to_string()).collect(),
            risk_score: risk,
            severity:   sev.to_owned(),
            model:      "gpt-4".to_owned(),
            org_id:     "org-test".to_owned(),
            metadata:   HashMap::new(),
        }
    }

    #[test]
    fn any_of_matches() {
        let c = Condition::AnyOf { pii_types: vec!["SSN".into(), "EMAIL".into()] };
        assert!(c.evaluate(&ctx(50.0, &["SSN"], "high")));
        assert!(!c.evaluate(&ctx(10.0, &["PHONE"], "low")));
    }

    #[test]
    fn all_of_requires_both() {
        let c = Condition::AllOf { pii_types: vec!["SSN".into(), "EMAIL".into()] };
        assert!(!c.evaluate(&ctx(50.0, &["SSN"], "high")));
        assert!(c.evaluate(&ctx(50.0, &["SSN", "EMAIL"], "high")));
    }

    #[test]
    fn risk_score_gte() {
        let c = Condition::RiskScoreGte { threshold: 80.0 };
        assert!(c.evaluate(&ctx(80.0, &[], "critical")));
        assert!(!c.evaluate(&ctx(79.9, &[], "high")));
    }

    #[test]
    fn model_prefix_case_insensitive() {
        let c = Condition::ModelPrefix { prefix: "gpt-".to_owned() };
        let mut ctx = ctx(0.0, &[], "none");
        ctx.model = "GPT-4o".to_owned();
        assert!(c.evaluate(&ctx));
    }

    #[test]
    fn and_condition() {
        let c = Condition::And { conditions: vec![
            Condition::RiskScoreGte { threshold: 50.0 },
            Condition::AnyOf { pii_types: vec!["SSN".into()] },
        ]};
        assert!(c.evaluate(&ctx(90.0, &["SSN"], "critical")));
        assert!(!c.evaluate(&ctx(90.0, &["EMAIL"], "high")));
    }

    #[test]
    fn not_condition() {
        let c = Condition::Not { condition: Box::new(Condition::Always) };
        assert!(!c.evaluate(&ctx(0.0, &[], "none")));
    }
}
