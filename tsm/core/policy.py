"""
TSM Policy Engine
=================
Configurable rules that sit on top of the detection layer.

Default policy mirrors the built-in severity tiers.
Custom rules let you extend or override for your organization.

Policy file: ~/.tsm/policy.json

Example policy.json:
    {
      "version": 1,
      "rules": [
        {"match": "project-codename", "action": "block",  "label": "CONFIDENTIAL"},
        {"match": "competitor.com",   "action": "redact", "label": "COMPETITOR_MENTION"}
      ],
      "model_allowlist": [],
      "model_blocklist": ["gpt-4-32k"],
      "require_local_for": ["CRITICAL", "HIGH"],
      "compliance": ["GDPR", "HIPAA"]
    }

Actions:
    block   — return error, don't forward
    redact  — replace match with [REDACTED:LABEL]
    flag    — log and forward unchanged
    allow   — explicit allow (overrides detections)
"""
from __future__ import annotations

import json
import pathlib
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

_POLICY_PATH = pathlib.Path.home() / ".tsm" / "policy.json"

# ── Compliance framework → PII type mapping ───────────────────────────────────
# Maps what each framework cares about so we can generate relevant reports.

COMPLIANCE_MAP: Dict[str, Dict[str, Any]] = {
    "GDPR": {
        "pii_types": ["EMAIL", "PHONE", "PASSPORT", "IP_ADDR", "DATE_OF_BIRTH", "STREET_ADDRESS", "IDENTITY_DISCLOSURE"],
        "article":   "Article 4 (personal data), Article 9 (sensitive data)",
        "action":    "redact or block",
    },
    "HIPAA": {
        "pii_types": ["SSN", "DATE_OF_BIRTH", "PHONE", "EMAIL", "STREET_ADDRESS", "MEDICAL_CONTEXT"],
        "article":   "45 CFR Part 164 (Safe Harbor de-identification)",
        "action":    "block",
    },
    "PCI-DSS": {
        "pii_types": ["CREDIT_CARD", "FINANCIAL_ACCOUNT"],
        "article":   "PCI DSS Requirement 3 (protect stored cardholder data)",
        "action":    "block",
    },
    "SOC2": {
        "pii_types": ["API_KEY", "AWS_KEY", "PASSWORD", "JWT", "OPENAI_KEY", "PRIVATE_KEY",
                      "CREDENTIALS_PAIR", "HIGH_ENTROPY_SECRET"],
        "article":   "CC6.1 (logical access security), CC6.7 (transmission encryption)",
        "action":    "block or redact",
    },
}

_DEFAULT_POLICY: Dict[str, Any] = {
    "version": 1,
    "rules": [],
    "model_allowlist": [],
    "model_blocklist": [],
    "require_local_for": ["CRITICAL"],
    "compliance": [],
}


@dataclass
class PolicyRule:
    match: str           # regex pattern or literal
    action: str          # block | redact | flag | allow
    label: str           # shown in logs / audit
    compiled: re.Pattern = field(init=False)

    def __post_init__(self):
        self.compiled = re.compile(re.escape(self.match), re.I) if not _is_regex(self.match) \
            else re.compile(self.match, re.I)


@dataclass
class PolicyDecision:
    action: str               # block | redact | flag | allow | pass
    triggered_rule: Optional[str] = None
    label: Optional[str] = None

    @property
    def is_blocked(self) -> bool:
        return self.action == "block"

    @property
    def is_redacted(self) -> bool:
        return self.action == "redact"


class PolicyEngine:
    """
    Evaluates requests against the active policy.

    Loading priority:
      1. ~/.tsm/policy.json (user policy, editable via tsm policy)
      2. Built-in defaults

    Usage:
        engine = PolicyEngine()
        decision = engine.evaluate(text, pii_types=["SSN"], model="gpt-4")
        if decision.is_blocked:
            return error_response
    """

    def __init__(self, path: pathlib.Path = _POLICY_PATH) -> None:
        self._path = path
        self._data = self._load()
        self._rules = self._compile_rules()

    # ── Public API ────────────────────────────────────────────

    def evaluate(
        self,
        text: str,
        pii_types: List[str],
        severity: str,
        model: str,
    ) -> PolicyDecision:
        """Evaluate a request against the active policy."""

        # 1. Model blocklist
        if model in self._data.get("model_blocklist", []):
            return PolicyDecision(action="block", triggered_rule="model_blocklist", label=f"MODEL:{model}")

        # 2. Custom text rules
        for rule in self._rules:
            if rule.compiled.search(text):
                return PolicyDecision(action=rule.action, triggered_rule=rule.match, label=rule.label)

        # 3. Severity-based local routing
        require_local = self._data.get("require_local_for", ["CRITICAL"])
        if severity in require_local:
            return PolicyDecision(action="route_local", triggered_rule="severity_policy", label=severity)

        return PolicyDecision(action="pass")

    def compliance_frameworks(self) -> List[str]:
        return self._data.get("compliance", [])

    def is_pii_type_covered(self, pii_type: str, framework: str) -> bool:
        """Return True if this PII type is covered by the given framework."""
        info = COMPLIANCE_MAP.get(framework, {})
        return pii_type in info.get("pii_types", [])

    def add_rule(self, match: str, action: str, label: str) -> None:
        """Add a custom rule and persist it."""
        self._data.setdefault("rules", []).append({
            "match": match, "action": action, "label": label,
        })
        self._rules = self._compile_rules()
        self._save()

    def enable_compliance(self, framework: str) -> None:
        """Add a compliance framework to the active policy."""
        if framework not in COMPLIANCE_MAP:
            raise ValueError(f"Unknown framework. Available: {', '.join(COMPLIANCE_MAP)}")
        frameworks = self._data.setdefault("compliance", [])
        if framework not in frameworks:
            frameworks.append(framework)
        self._save()

    def show(self) -> Dict[str, Any]:
        return dict(self._data)

    def reset(self) -> None:
        self._data = dict(_DEFAULT_POLICY)
        self._rules = []
        self._save()

    # ── Internal ──────────────────────────────────────────────

    def _load(self) -> Dict[str, Any]:
        if self._path.exists():
            try:
                with open(self._path, encoding="utf-8") as f:
                    data = json.load(f)
                    # Merge with defaults so new keys always exist
                    merged = dict(_DEFAULT_POLICY)
                    merged.update(data)
                    return merged
            except Exception:
                pass
        return dict(_DEFAULT_POLICY)

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._path, "w", encoding="utf-8") as f:
            json.dump(self._data, f, indent=2)

    def _compile_rules(self) -> List[PolicyRule]:
        rules = []
        for r in self._data.get("rules", []):
            try:
                rules.append(PolicyRule(
                    match=r["match"],
                    action=r.get("action", "flag"),
                    label=r.get("label", r["match"]),
                ))
            except Exception:
                pass
        return rules


def _is_regex(s: str) -> bool:
    """Return True if the string contains regex metacharacters."""
    return bool(re.search(r"[.*+?^${}()|[\]\\]", s))
