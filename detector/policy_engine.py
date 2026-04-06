"""
Policy Engine — YAML/JSON rule evaluator
=========================================
Replaces hardcoded if/else logic with a declarative rule DSL.

Rule format (stored in ~/.tsm/policy.yaml or passed via API):

  rules:
    - name: block_secrets
      priority: 1
      condition:
        any_of: [GITHUB_TOKEN, OPENAI_KEY, AWS_KEY, ANTHROPIC_KEY, PRIVATE_KEY]
      action: block

    - name: dev_redact_pii
      priority: 10
      condition:
        contains_pii: true
        user_role: dev
      action: redact

    - name: high_risk_local
      priority: 20
      condition:
        risk_score_gte: 70
      action: route_local

    - name: jailbreak_block
      priority: 1
      condition:
        any_of: [JAILBREAK]
      action: block

Default built-in rules apply when no user rules match.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ── Rule DSL ──────────────────────────────────────────────────────────────────

@dataclass
class PolicyRule:
    name:      str
    condition: dict[str, Any]
    action:    str              # allow | redact | block | route_local
    priority:  int = 100       # lower = higher priority

    def matches(
        self,
        pii_types:  list[str],
        risk_score: float,
        severity:   str,
        user_role:  str | None,
        model:      str,
        metadata:   dict[str, Any],
    ) -> bool:
        c = self.condition

        # any_of: block/route if any listed PII type is present
        if "any_of" in c:
            if not any(t in pii_types for t in c["any_of"]):
                return False

        # all_of: all must be present
        if "all_of" in c:
            if not all(t in pii_types for t in c["all_of"]):
                return False

        # contains_pii: True = must have at least one PII type
        if "contains_pii" in c:
            has_pii = len(pii_types) > 0
            if c["contains_pii"] != has_pii:
                return False

        # risk_score_gte: risk must be >= threshold
        if "risk_score_gte" in c:
            if risk_score < c["risk_score_gte"]:
                return False

        # risk_score_lt: risk must be < threshold
        if "risk_score_lt" in c:
            if risk_score >= c["risk_score_lt"]:
                return False

        # severity: must match exactly
        if "severity" in c:
            if severity != c["severity"]:
                return False

        # user_role: must match
        if "user_role" in c:
            if user_role != c["user_role"]:
                return False

        # model_prefix: model name must start with this
        if "model_prefix" in c:
            if not model.startswith(c["model_prefix"]):
                return False

        # metadata: arbitrary key/value match
        if "metadata" in c:
            for k, v in c["metadata"].items():
                if metadata.get(k) != v:
                    return False

        return True


@dataclass
class PolicyResult:
    action:    str
    rule_name: str | None = None


# ── Built-in rules (always present, can be overridden) ───────────────────────

_BUILTIN_RULES: list[PolicyRule] = [
    PolicyRule(
        name="block_jailbreak",
        priority=1,
        condition={"any_of": ["JAILBREAK"]},
        action="block",
    ),
    PolicyRule(
        name="block_secrets",
        priority=2,
        condition={"any_of": ["GITHUB_TOKEN", "OPENAI_KEY", "ANTHROPIC_KEY",
                               "AWS_KEY", "STRIPE_SECRET", "PRIVATE_KEY",
                               "SENDGRID_KEY", "GITLAB_TOKEN"]},
        action="block",
    ),
    PolicyRule(
        name="local_critical_pii",
        priority=10,
        condition={"severity": "critical"},
        action="route_local",
    ),
    PolicyRule(
        name="redact_high_pii",
        priority=20,
        condition={"severity": "high"},
        action="redact",
    ),
    PolicyRule(
        name="redact_medium_risk",
        priority=30,
        condition={"risk_score_gte": 35},
        action="redact",
    ),
    PolicyRule(
        name="allow_clean",
        priority=999,
        condition={"risk_score_lt": 10},
        action="allow",
    ),
]


# ── PolicyEngine ──────────────────────────────────────────────────────────────

_POLICY_PATH = Path(os.environ.get("TSM_POLICY_PATH", Path.home() / ".tsm" / "policy.json"))


class PolicyEngine:
    def __init__(self) -> None:
        self._custom_rules: list[PolicyRule] = []
        self._load_persisted()

    def _load_persisted(self) -> None:
        if _POLICY_PATH.exists():
            try:
                data = json.loads(_POLICY_PATH.read_text())
                for r in data.get("rules", []):
                    self._custom_rules.append(PolicyRule(**r))
            except Exception:
                pass

    def _persist(self) -> None:
        _POLICY_PATH.parent.mkdir(parents=True, exist_ok=True)
        rules = [{"name": r.name, "condition": r.condition, "action": r.action, "priority": r.priority}
                 for r in self._custom_rules]
        _POLICY_PATH.write_text(json.dumps({"rules": rules}, indent=2))

    def add_rule(self, rule: PolicyRule) -> None:
        # Replace existing rule with same name
        self._custom_rules = [r for r in self._custom_rules if r.name != rule.name]
        self._custom_rules.append(rule)
        self._persist()

    def remove_rule(self, name: str) -> bool:
        before = len(self._custom_rules)
        self._custom_rules = [r for r in self._custom_rules if r.name != name]
        self._persist()
        return len(self._custom_rules) < before

    def evaluate(
        self,
        pii_types:  list[str],
        risk_score: float,
        severity:   str,
        user_role:  str | None,
        model:      str,
        metadata:   dict[str, Any],
    ) -> PolicyResult:
        # Custom rules take priority over built-ins (sorted by priority asc)
        all_rules = sorted(self._custom_rules + _BUILTIN_RULES, key=lambda r: r.priority)

        for rule in all_rules:
            if rule.matches(pii_types, risk_score, severity, user_role, model, metadata):
                return PolicyResult(action=rule.action, rule_name=rule.name)

        # Default: allow if nothing matched
        return PolicyResult(action="allow", rule_name=None)

    def rules_as_dict(self) -> list[dict]:
        all_rules = sorted(self._custom_rules + _BUILTIN_RULES, key=lambda r: r.priority)
        return [
            {
                "name":      r.name,
                "priority":  r.priority,
                "condition": r.condition,
                "action":    r.action,
                "source":    "custom" if r in self._custom_rules else "builtin",
            }
            for r in all_rules
        ]
