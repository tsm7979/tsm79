/// Policy rule engine — evaluates ordered rules against a request context.
///
/// Rules are stored in a `RwLock<Vec<PolicyRule>>` sorted by priority ascending.
/// The engine is safe to read concurrently; writes acquire an exclusive lock.
use std::sync::{Arc, RwLock};

use super::rule::{Action, Condition, EvalContext, PolicyResult, PolicyRule};

// serde needed for hot-reload JSON parsing in reload_from_json()
#[allow(unused_imports)]
use serde::Deserialize;

pub struct PolicyEngine {
    /// Rules sorted by `priority` ascending (lowest value = highest priority).
    rules: Arc<RwLock<Vec<PolicyRule>>>,
}

impl PolicyEngine {
    pub fn new() -> Self {
        PolicyEngine {
            rules: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Evaluate all enabled rules in priority order.
    /// Returns the action from the first matching rule, or `Action::Allow` if
    /// no rule matches.
    pub fn evaluate(&self, ctx: &EvalContext) -> PolicyResult {
        let rules = self.rules.read().expect("policy RwLock poisoned");
        for rule in rules.iter() {
            if !rule.enabled {
                continue;
            }
            if rule.condition.evaluate(ctx) {
                return PolicyResult {
                    action:    rule.action.clone(),
                    rule_name: rule.name.clone(),
                };
            }
        }
        // Default: allow (no rule matched)
        PolicyResult {
            action:    Action::Allow,
            rule_name: "<default-allow>".to_owned(),
        }
    }

    /// Add or replace a rule.  If a rule with the same name already exists it
    /// is replaced in-place; otherwise the new rule is inserted and the list
    /// is re-sorted by priority.
    pub fn upsert_rule(&self, rule: PolicyRule) {
        let mut rules = self.rules.write().expect("policy RwLock poisoned");
        if let Some(pos) = rules.iter().position(|r| r.name == rule.name) {
            rules[pos] = rule;
        } else {
            rules.push(rule);
        }
        rules.sort_by_key(|r| r.priority);
    }

    /// Remove a rule by name.  Returns `true` if the rule was found and removed.
    pub fn remove_rule(&self, name: &str) -> bool {
        let mut rules = self.rules.write().expect("policy RwLock poisoned");
        let before = rules.len();
        rules.retain(|r| r.name != name);
        rules.len() < before
    }

    /// Enable or disable a rule by name without removing it.
    pub fn set_enabled(&self, name: &str, enabled: bool) -> bool {
        let mut rules = self.rules.write().expect("policy RwLock poisoned");
        if let Some(r) = rules.iter_mut().find(|r| r.name == name) {
            r.enabled = enabled;
            true
        } else {
            false
        }
    }

    /// Return a snapshot of all rule names and their current enabled state.
    pub fn list_rules(&self) -> Vec<(String, i32, bool)> {
        let rules = self.rules.read().expect("policy RwLock poisoned");
        rules.iter().map(|r| (r.name.clone(), r.priority, r.enabled)).collect()
    }

    /// Load the built-in default rules.  Called once at startup before serving.
    pub fn load_builtin_rules(&self) {
        use super::builtin::builtin_rules;
        for rule in builtin_rules() {
            self.upsert_rule(rule);
        }
    }

    /// Hot-reload: replace the entire ruleset from a JSON string pushed by the
    /// control plane.  The JSON format matches the control plane's `Snapshot.rules`
    /// array: `[{"name":"...","action":"block","priority":10,"enabled":true,
    ///            "condition":{"risk_score_gte":80}}]`.
    ///
    /// On parse failure, logs a warning and keeps the existing rules.
    pub fn reload_from_json(&self, json: &str) {
        #[derive(serde::Deserialize)]
        struct WireRule {
            name:      String,
            action:    String,
            priority:  i32,
            #[serde(default = "default_true")]
            enabled:   bool,
            condition: serde_json::Value,
        }
        fn default_true() -> bool { true }

        // The JSON from the control plane is the full Snapshot object.
        // Try to extract `rules` array from it.
        let rules_val: serde_json::Value = match serde_json::from_str(json) {
            Ok(v)  => v,
            Err(e) => {
                crate::telemetry::emit("warn", "policy", "hot-reload JSON parse failed", &[
                    ("err", e.to_string()),
                ]);
                return;
            }
        };
        let arr = rules_val.get("rules")
            .or(Some(&rules_val)) // allow bare array too
            .and_then(|v| v.as_array());
        let arr = match arr {
            Some(a) => a,
            None    => {
                crate::telemetry::emit("warn", "policy", "hot-reload: no rules array in JSON", &[]);
                return;
            }
        };

        let mut new_rules: Vec<PolicyRule> = Vec::new();
        for item in arr {
            let w: WireRule = match serde_json::from_value(item.clone()) {
                Ok(r)  => r,
                Err(e) => {
                    crate::telemetry::emit("warn", "policy", "skip malformed rule", &[
                        ("err", e.to_string()),
                    ]);
                    continue;
                }
            };
            let action = match w.action.as_str() {
                "block"       => Action::Block { reason: w.name.clone() },
                "redact"      => Action::Redact,
                "route_local" => Action::RouteLocal,
                _             => Action::Allow,
            };
            // Parse condition: support {"risk_score_gte": N} and {"always": true}
            let condition = parse_condition_from_json(&w.condition);
            new_rules.push(PolicyRule::new(&w.name, w.priority, condition, action).with_enabled(w.enabled));
        }

        // Sort and atomically replace
        new_rules.sort_by_key(|r| r.priority);
        let mut rules = self.rules.write().expect("policy RwLock poisoned");
        *rules = new_rules;
        crate::telemetry::emit("info", "policy", "rules hot-reloaded", &[
            ("count", rules.len().to_string()),
        ]);
    }
}

fn parse_condition_from_json(v: &serde_json::Value) -> Condition {
    if v.get("always").and_then(|b| b.as_bool()).unwrap_or(false) {
        return Condition::Always;
    }
    if let Some(threshold) = v.get("risk_score_gte").and_then(|n| n.as_f64()) {
        return Condition::RiskScoreGte { threshold };
    }
    if let Some(types_arr) = v.get("pii_types").and_then(|a| a.as_array()) {
        let pii: Vec<String> = types_arr.iter()
            .filter_map(|t| t.as_str().map(str::to_owned))
            .collect();
        if !pii.is_empty() {
            return Condition::AnyOf { pii_types: pii };
        }
    }
    // Default: always match (permissive fallback)
    Condition::Always
}

impl Default for PolicyEngine {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn ctx(risk: f64, pii: &[&str], sev: &str) -> EvalContext {
        EvalContext {
            pii_types:  pii.iter().map(|s| s.to_string()).collect(),
            risk_score: risk,
            severity:   sev.to_owned(),
            model:      "gpt-4".to_owned(),
            org_id:     "org1".to_owned(),
            metadata:   HashMap::new(),
        }
    }

    #[test]
    fn no_rules_allows() {
        let eng = PolicyEngine::new();
        let res = eng.evaluate(&ctx(50.0, &["SSN"], "high"));
        assert!(matches!(res.action, Action::Allow));
        assert_eq!(res.rule_name, "<default-allow>");
    }

    #[test]
    fn first_matching_rule_wins() {
        let eng = PolicyEngine::new();
        eng.upsert_rule(PolicyRule::new(
            "block-critical",
            10,
            Condition::RiskScoreGte { threshold: 80.0 },
            Action::Block { reason: "high risk".into() },
        ));
        eng.upsert_rule(PolicyRule::new(
            "redact-medium",
            20,
            Condition::RiskScoreGte { threshold: 40.0 },
            Action::Redact,
        ));

        // risk=90 → should hit block-critical (priority 10) first
        let res = eng.evaluate(&ctx(90.0, &["SSN"], "critical"));
        assert!(matches!(res.action, Action::Block { .. }));
        assert_eq!(res.rule_name, "block-critical");
    }

    #[test]
    fn lower_priority_fires_when_high_not_matched() {
        let eng = PolicyEngine::new();
        eng.upsert_rule(PolicyRule::new(
            "block-critical",
            10,
            Condition::RiskScoreGte { threshold: 80.0 },
            Action::Block { reason: "high risk".into() },
        ));
        eng.upsert_rule(PolicyRule::new(
            "redact-medium",
            20,
            Condition::RiskScoreGte { threshold: 40.0 },
            Action::Redact,
        ));

        // risk=50 → misses block (80) but hits redact (40)
        let res = eng.evaluate(&ctx(50.0, &["EMAIL"], "medium"));
        assert!(matches!(res.action, Action::Redact));
        assert_eq!(res.rule_name, "redact-medium");
    }

    #[test]
    fn remove_rule_works() {
        let eng = PolicyEngine::new();
        eng.upsert_rule(PolicyRule::new(
            "test-rule", 10, Condition::Always, Action::Block { reason: "test".into() },
        ));
        assert!(eng.remove_rule("test-rule"));
        assert!(!eng.remove_rule("test-rule")); // already gone

        // Should fall through to default-allow
        let res = eng.evaluate(&ctx(90.0, &[], "critical"));
        assert!(matches!(res.action, Action::Allow));
    }

    #[test]
    fn disabled_rule_skipped() {
        let eng = PolicyEngine::new();
        eng.upsert_rule(PolicyRule::new(
            "catch-all", 10, Condition::Always, Action::Block { reason: "all".into() },
        ));
        eng.set_enabled("catch-all", false);
        let res = eng.evaluate(&ctx(50.0, &[], "none"));
        assert!(matches!(res.action, Action::Allow));
    }

    #[test]
    fn upsert_replaces_existing() {
        let eng = PolicyEngine::new();
        eng.upsert_rule(PolicyRule::new("r1", 10, Condition::Always, Action::Redact));
        eng.upsert_rule(PolicyRule::new("r1", 10, Condition::Always, Action::Allow));
        let rules = eng.list_rules();
        assert_eq!(rules.len(), 1);
        let res = eng.evaluate(&ctx(0.0, &[], "none"));
        assert!(matches!(res.action, Action::Allow));
    }

    #[test]
    fn builtin_rules_load_without_panic() {
        let eng = PolicyEngine::new();
        eng.load_builtin_rules();
        let rules = eng.list_rules();
        assert!(!rules.is_empty(), "should have builtin rules");
    }
}
