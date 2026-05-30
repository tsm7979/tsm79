/// Six built-in policy rules that match TSMv1's default behaviour.
///
/// Rules are evaluated in priority order (lowest number = highest priority).
/// The built-in set is designed to be safe-by-default: any critical-severity
/// PII or secret is blocked; medium/redactable PII is redacted; jailbreaks
/// are blocked; low-risk requests are allowed.
use super::rule::{Action, Condition, PolicyRule};

/// Return the six default rules, sorted by priority ascending.
pub fn builtin_rules() -> Vec<PolicyRule> {
    vec![
        // ── Priority 10: Block jailbreak attempts ─────────────────────────────
        PolicyRule::new(
            "builtin-block-jailbreak",
            10,
            Condition::AnyOf { pii_types: vec!["JAILBREAK".to_owned()] },
            Action::Block { reason: "Jailbreak attempt detected".to_owned() },
        ),

        // ── Priority 20: Block critical secrets (API keys, private keys) ──────
        PolicyRule::new(
            "builtin-block-secrets",
            20,
            Condition::And { conditions: vec![
                Condition::AnyOf { pii_types: vec![
                    "OPENAI_KEY".to_owned(),
                    "ANTHROPIC_KEY".to_owned(),
                    "AWS_KEY".to_owned(),
                    "GITHUB_TOKEN".to_owned(),
                    "STRIPE_KEY".to_owned(),
                    "PRIVATE_KEY".to_owned(),
                    "SENDGRID_KEY".to_owned(),
                    "HUGGINGFACE_KEY".to_owned(),
                    "GITLAB_TOKEN".to_owned(),
                ]},
                Condition::SeverityIs { severity: "critical".to_owned() },
            ]},
            Action::Block { reason: "Critical secret detected in request".to_owned() },
        ),

        // ── Priority 30: Block high-risk PII (SSN + risk ≥ 80) ───────────────
        PolicyRule::new(
            "builtin-block-high-pii",
            30,
            Condition::And { conditions: vec![
                Condition::AnyOf { pii_types: vec!["SSN".to_owned(), "CREDIT_CARD".to_owned()] },
                Condition::RiskScoreGte { threshold: 80.0 },
            ]},
            Action::Block { reason: "High-risk PII (SSN/credit card) detected".to_owned() },
        ),

        // ── Priority 40: Redact medium-risk PII (email, phone, etc.) ─────────
        PolicyRule::new(
            "builtin-redact-medium-pii",
            40,
            Condition::And { conditions: vec![
                Condition::AnyOf { pii_types: vec![
                    "EMAIL".to_owned(),
                    "PHONE".to_owned(),
                    "SSN".to_owned(),
                    "CREDIT_CARD".to_owned(),
                ]},
                Condition::RiskScoreGte { threshold: 35.0 },
                Condition::RiskScoreLt  { threshold: 80.0 },
            ]},
            Action::Redact,
        ),

        // ── Priority 45: Quarantine NER-ambiguous content for human review ────
        // Named-entity signals (names, passport #, DOB, maiden name, tax id) that
        // the fast path + ML triage could NOT resolve are HELD for manual review
        // rather than forwarded — the firewall's `quarantine` verdict. Distinct
        // from block (reject): the request is isolated, not denied. Completes the
        // PDF verdict taxonomy (allow / redact / route / block / quarantine).
        PolicyRule::new(
            "builtin-quarantine-ner-review",
            45,
            Condition::AnyOf { pii_types: vec!["NER_REVIEW".to_owned()] },
            Action::Quarantine { reason: "Named-entity content held for manual review".to_owned() },
        ),

        // ── Priority 50: Route local if any PII detected ──────────────────────
        // Falls through from rules 10-40 for low-risk PII that needn't be
        // blocked or redacted but should stay on-prem.
        PolicyRule::new(
            "builtin-route-local-pii",
            50,
            Condition::And { conditions: vec![
                Condition::Or { conditions: vec![
                    Condition::AnyOf { pii_types: vec![
                        "EMAIL".to_owned(), "PHONE".to_owned(),
                        "SSN".to_owned(),   "CREDIT_CARD".to_owned(),
                    ]},
                    Condition::RiskScoreGte { threshold: 25.0 },
                ]},
                Condition::RiskScoreLt { threshold: 35.0 },
            ]},
            Action::RouteLocal,
        ),

        // ── Priority 90: Fail-secure block for high risk of ANY kind ──────────
        // Defense in depth: a request scored at/above the block threshold must
        // never be allowed just because its finding type isn't in the recognized
        // PII/secret sets above (e.g. encoded/BPE-prohibited payloads, ONNX
        // ENCODED_SECRET, or future detector labels). Severity ≥ critical == risk ≥ 80.
        PolicyRule::new(
            "builtin-block-high-risk",
            90,
            Condition::RiskScoreGte { threshold: 80.0 },
            Action::Block { reason: "High-risk content blocked (fail-secure)".to_owned() },
        ),

        // ── Priority 95: Fail-secure redact for medium-high risk of ANY kind ──
        // Anything in the 60–80 band that no typed rule caught is redacted rather
        // than forwarded clean — never silently allow medium-high-risk content.
        PolicyRule::new(
            "builtin-redact-high-risk",
            95,
            Condition::RiskScoreGte { threshold: 60.0 },
            Action::Redact,
        ),

        // ── Priority 100: Allow anything that passed the above rules ──────────
        PolicyRule::new(
            "builtin-default-allow",
            100,
            Condition::Always,
            Action::Allow,
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::engine::PolicyEngine;
    use super::super::rule::EvalContext;
    use std::collections::HashMap;

    fn ctx(risk: f64, pii: &[&str], sev: &str) -> EvalContext {
        EvalContext {
            pii_types:  pii.iter().map(|s| s.to_string()).collect(),
            risk_score: risk,
            severity:   sev.to_owned(),
            model:      "gpt-4".to_owned(),
            org_id:     "org-1".to_owned(),
            metadata:   HashMap::new(),
        }
    }

    fn engine() -> PolicyEngine {
        let eng = PolicyEngine::new();
        eng.load_builtin_rules();
        eng
    }

    #[test]
    fn jailbreak_blocked() {
        let res = engine().evaluate(&ctx(75.0, &["JAILBREAK"], "high"));
        assert!(matches!(res.action, Action::Block { .. }));
        assert_eq!(res.rule_name, "builtin-block-jailbreak");
    }

    #[test]
    fn openai_key_blocked() {
        let res = engine().evaluate(&ctx(90.0, &["OPENAI_KEY"], "critical"));
        assert!(matches!(res.action, Action::Block { .. }));
        assert_eq!(res.rule_name, "builtin-block-secrets");
    }

    #[test]
    fn high_risk_ssn_blocked() {
        let res = engine().evaluate(&ctx(85.0, &["SSN"], "critical"));
        assert!(matches!(res.action, Action::Block { .. }));
        assert_eq!(res.rule_name, "builtin-block-high-pii");
    }

    #[test]
    fn medium_risk_email_redacted() {
        let res = engine().evaluate(&ctx(50.0, &["EMAIL"], "medium"));
        assert!(matches!(res.action, Action::Redact));
        assert_eq!(res.rule_name, "builtin-redact-medium-pii");
    }

    #[test]
    fn low_risk_pii_routes_local() {
        let res = engine().evaluate(&ctx(30.0, &["EMAIL"], "low"));
        assert!(matches!(res.action, Action::RouteLocal));
        assert_eq!(res.rule_name, "builtin-route-local-pii");
    }

    #[test]
    fn ner_review_quarantined() {
        // Unresolved named-entity content → held for review (5th verdict).
        let res = engine().evaluate(&ctx(40.0, &["NER_REVIEW"], "medium"));
        assert!(matches!(res.action, Action::Quarantine { .. }));
        assert_eq!(res.rule_name, "builtin-quarantine-ner-review");
    }

    #[test]
    fn clean_text_allowed() {
        let res = engine().evaluate(&ctx(0.0, &[], "none"));
        assert!(matches!(res.action, Action::Allow));
        assert_eq!(res.rule_name, "builtin-default-allow");
    }
}
