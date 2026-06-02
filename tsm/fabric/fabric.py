"""
TSM Fabric — unified facade
===========================
One object that runs the whole trust fabric for a request:

    Identity  →  Policy  →  Trust Engine (AI/Code/Human)  →  Routing  →  Verification

``TrustFabric.handle(...)`` returns a :class:`FabricResult` and leaves a signed,
chained attestation behind. The Recovery Engine is exposed for incident response
(it is a different flow from request handling and is invoked on detected threats).

The final verdict is the **most restrictive** of the payload-safety decision (the
AI→Code→Human engine) and the governance decision (the Policy DSL) — payload
safety can only tighten governance, never loosen it. Pure standard library.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from tsm.engine import RiskTier, TrustContext, TrustEngine, Verdict
from tsm.engine.adapters import default_engine
from tsm.fabric.identity import IdentityRegistry
from tsm.fabric.recovery import RecoveryEngine
from tsm.fabric.routing import RoutingEngine
from tsm.fabric.verification import AttestationLog

# Restrictiveness ordering for combining engine + policy verdicts.
_SAFETY_RANK = {"allow": 0, "escalate": 1, "quarantine": 2, "block": 3}

# A policy action expressed as a trust verdict. "route"/"redact"/"flag" are not
# restrictions (they're handling hints), so they map to ALLOW.
_POLICY_TO_VERDICT = {
    "allow": "allow", "flag": "allow", "redact": "allow", "route": "allow",
    "require_approval": "escalate", "escalate": "escalate",
    "quarantine": "quarantine", "block": "block",
}


@dataclass(frozen=True)
class FabricResult:
    verdict: str
    destination: str
    principal: Optional[str]
    mode: str
    policy_rule: Optional[str]
    attestation_id: str
    degraded: bool
    reason: str

    @property
    def allowed(self) -> bool:
        return self.verdict == "allow"

    def as_dict(self) -> dict:
        return {
            "verdict": self.verdict, "destination": self.destination,
            "principal": self.principal, "mode": self.mode,
            "policy_rule": self.policy_rule, "attestation_id": self.attestation_id,
            "degraded": self.degraded, "reason": self.reason,
        }


class TrustFabric:
    """The five engines + the arbiter, wired into one request pipeline."""

    def __init__(self, *, identity: Optional[IdentityRegistry] = None,
                 policy=None, engine: Optional[TrustEngine] = None,
                 router: Optional[RoutingEngine] = None,
                 attestations: Optional[AttestationLog] = None,
                 recovery: Optional[RecoveryEngine] = None) -> None:
        self.identity = identity or IdentityRegistry()
        self.policy = policy
        self.engine = engine or default_engine()
        self.router = router or RoutingEngine()
        self.attestations = attestations or AttestationLog()
        self.recovery = recovery or RecoveryEngine()

    def handle(self, *, payload: str = "", session: Optional[str] = None,
               principal_id: Optional[str] = None, action: str = "ai.request",
               classification: str = "public", dest_trust: float = 100.0,
               risk: Optional[RiskTier] = None, subject: str = "req") -> FabricResult:
        # 1. Identity — who is requesting?
        principal = None
        if session:
            info = self.identity.verify_session(session)
            principal = info.principal if info else None
        elif principal_id:
            principal = self.identity.get(principal_id)

        # 2. Policy — governance decision (classification, destination trust, action).
        outcome = None
        if self.policy is not None:
            ctx = {
                "action": action,
                "data": {"classification": classification},
                "destination": {"trust": dest_trust},
                "identity": {
                    "kind": principal.kind.value if principal else "unknown",
                    "trust": principal.trust_score if principal else 0.0,
                },
            }
            outcome = self.policy.evaluate(ctx)

        # 3. Trust Engine — payload-safety decision (AI/Code/Human arbiter).
        if risk is not None:
            rtier = risk
        elif outcome and outcome.action in ("block", "require_approval", "quarantine"):
            rtier = RiskTier.HIGH
        else:
            rtier = RiskTier.LOW
        decision = self.engine.decide(TrustContext(
            payload=payload, action=action, risk=rtier,
            metadata={"principal": principal.id if principal else None}))

        # 4. Combine — most restrictive of payload safety and governance.
        engine_v = decision.verdict.value
        policy_v = _POLICY_TO_VERDICT.get(outcome.action, "allow") if outcome else "allow"
        final = engine_v if _SAFETY_RANK.get(engine_v, 0) >= _SAFETY_RANK.get(policy_v, 0) else policy_v

        # 5. Routing — where should this go?
        routing = self.router.route(verdict=final, policy_outcome=outcome)

        # 6. Verification — sign + chain an attestation of the whole decision.
        att = self.attestations.attest(
            actor=principal.id if principal else "anonymous",
            action=action, subject=subject, decision=final,
            policy_rule=(outcome.matched_rule if (outcome and outcome.matched_rule) else decision.rule),
            reason=f"{decision.explanation} | route={routing.destination.value}")

        return FabricResult(
            verdict=final, destination=routing.destination.value,
            principal=principal.id if principal else None, mode=decision.mode.value,
            policy_rule=outcome.matched_rule if outcome else None,
            attestation_id=att.id, degraded=routing.degraded, reason=routing.reason)

    def verify_audit(self):
        """Convenience: verify the attestation chain. Returns ``(ok, count)``."""
        return self.attestations.verify_chain()
