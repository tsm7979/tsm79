"""
Policy loader — the DATA-PLANE side of control/data-plane separation.

The data plane loads signed policy bundles and refuses anything that doesn't
verify against a trusted operator key. Core guarantees:

  - A bundle with a bad/absent signature is REJECTED; the loader keeps the
    last-known-good IR (fail-closed on policy: never downgrade to "no policy"
    because an attacker pushed a broken bundle).
  - Version must be monotonic: an older or replayed bundle is rejected
    (anti-rollback).
  - Trusted keys are configured out-of-band (operator provisioning), not taken
    from the bundle itself.

This module deliberately holds NO authoring logic. Authoring lives in
policy_bundle.author_and_sign() on the control plane. The data plane only
verifies + activates.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Optional

from detector.policy_bundle import (
    SignedBundle,
    PolicyVerifyError,
    verify_bundle,
)

log = logging.getLogger(__name__)


@dataclass
class LoadResult:
    accepted: bool
    reason: str
    version: int = 0
    rule_count: int = 0


class PolicyLoader:
    """Holds the active (verified) policy IR for the data plane. Thread-safety:
    callers serialise load(); reads of active_ir are atomic dict references."""

    def __init__(self, trusted_pubkeys: set[str]) -> None:
        if not trusted_pubkeys:
            # A loader with no trust anchors can never accept policy — that's a
            # misconfiguration, not a safe default. Make it loud.
            log.warning("PolicyLoader created with NO trusted pubkeys; all loads will reject")
        self._trusted = set(trusted_pubkeys)
        self._active_ir: Optional[dict[str, Any]] = None
        self._active_version = 0

    def load(self, bundle: SignedBundle) -> LoadResult:
        """Verify + activate a bundle. On any failure, the active policy is left
        unchanged (last-known-good preserved)."""
        # 1. cryptographic verification (trust + integrity + authenticity)
        try:
            ir = verify_bundle(bundle, trusted_pubkeys=self._trusted)
        except PolicyVerifyError as e:
            log.error("policy bundle REJECTED: %s", e)
            return LoadResult(False, f"rejected: {e}", self._active_version,
                              self._rule_count())

        # 2. anti-rollback: version must strictly increase
        if bundle.version <= self._active_version:
            msg = (f"rejected: version {bundle.version} <= active "
                   f"{self._active_version} (rollback/replay)")
            log.error("policy bundle %s", msg)
            return LoadResult(False, msg, self._active_version, self._rule_count())

        # 3. activate
        self._active_ir = ir
        self._active_version = bundle.version
        rc = len(ir.get("rules", []))
        log.info("policy activated: v%d, %d rules, workspace=%s",
                 bundle.version, rc, ir.get("workspace", "default"))
        return LoadResult(True, "accepted", bundle.version, rc)

    @property
    def active_ir(self) -> Optional[dict[str, Any]]:
        return self._active_ir

    @property
    def active_version(self) -> int:
        return self._active_version

    def _rule_count(self) -> int:
        return len(self._active_ir.get("rules", [])) if self._active_ir else 0

    def evaluate_ir(self, signals: dict[str, Any]) -> dict[str, Any]:
        """Execute the active IR against a request's detection signals.
        First-match-wins by the IR's frozen priority order. Returns the chosen
        rule + action, or a safe default.

        `signals` is the detector output, e.g.:
          {"pii_types": [...], "severity": "critical", "risk_score": 92,
           "user_role": "...", "model": "gpt-4o", "detector_signals": [...],
           "known_bad": True, "obfuscation": 0.6}
        """
        if not self._active_ir:
            # No policy loaded -> fail closed on anything non-trivial.
            return {"action": "quarantine", "rule": "_no_policy",
                    "reason": "no signed policy loaded; fail-closed"}

        for rule in self._active_ir["rules"]:
            if _matches(rule.get("when", {}), signals):
                return {
                    "action": rule["action"],
                    "rule": rule["id"],
                    "reason": rule.get("reason", ""),
                    **({"target": rule["target"]} if "target" in rule else {}),
                }
        return {"action": "allow", "rule": "_default_allow", "reason": "no rule matched"}


# ── Matcher evaluation (pure, deterministic) ─────────────────────────────────
def _matches(when: dict[str, Any], sig: dict[str, Any]) -> bool:
    if not when:
        return True  # empty matcher = always (use for default rules)
    for key, val in when.items():
        if not _match_one(key, val, sig):
            return False
    return True


def _match_one(key: str, val: Any, sig: dict[str, Any]) -> bool:
    if key == "any_of":
        return any(_matches(sub, sig) for sub in val)
    if key == "all_of":
        return all(_matches(sub, sig) for sub in val)
    if key == "not":
        return not _matches(val, sig)
    if key == "contains_pii":
        want = val if isinstance(val, list) else [val]
        have = set(sig.get("pii_types", []))
        return any(w in have for w in want)
    if key == "severity":
        return sig.get("severity") == val
    if key == "risk_score_gte":
        return float(sig.get("risk_score", 0)) >= float(val)
    if key == "user_role":
        return sig.get("user_role") == val
    if key == "model_prefix":
        return str(sig.get("model", "")).startswith(str(val))
    if key == "detector_signal":
        return val in set(sig.get("detector_signals", []))
    if key == "known_bad":
        return bool(sig.get("known_bad", False)) == bool(val)
    if key == "obfuscation_gte":
        return float(sig.get("obfuscation", 0)) >= float(val)
    return False
