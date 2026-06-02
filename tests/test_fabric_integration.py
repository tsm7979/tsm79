"""
Integration: the Trust Fabric primitives composing into one request pipeline —
Identity -> Policy -> Trust Engine (AI/Code/Human) -> Verification.

This is Product 1 (the AI control plane) expressed through Product 2 (the trust
fabric): the same flow that any workload — not just AI — would travel.
"""
from tsm.engine import (
    CallableSource,
    Layer,
    RiskTier,
    TrustContext,
    TrustEngine,
    Verdict,
)
from tsm.fabric import AttestationLog, IdentityRegistry, parse_policy

POLICY = """
when data.classification == "secret" then route local
when destination.trust < 80 then block
when action == "destructive" then require_approval
default allow
"""


def _pipeline(reg, log, policy, *, principal, request):
    """Identity -> Policy -> Trust Engine -> signed Attestation. Returns decision."""
    # 1. Identity: issue + verify a signed session for the caller.
    token = reg.issue_session(principal.id, scopes=("ai.request",))
    session = reg.verify_session(token)
    assert session is not None, "session must verify"

    # 2. Policy: evaluate the trust language against request + identity context.
    ctx = {
        "action": request.get("action", "ai.request"),
        "data": {"classification": request.get("classification", "public")},
        "destination": {"trust": request.get("dest_trust", 100)},
        "identity": {"kind": session.principal.kind.value,
                     "trust": session.principal.trust_score},
    }
    outcome = policy.evaluate(ctx)

    # 3. Trust Engine: the Code layer enforces the policy outcome deterministically.
    policy_to_verdict = {
        "block": Verdict.BLOCK,
        "route": Verdict.QUARANTINE,        # route-local == isolate from cloud
        "require_approval": Verdict.ESCALATE,
        "quarantine": Verdict.QUARANTINE,
        "allow": Verdict.ALLOW,
    }
    verdict = policy_to_verdict.get(outcome.action, Verdict.ESCALATE)
    code = CallableSource(Layer.CODE,
                          lambda c, v=verdict: (v, 1.0, f"policy:{outcome.action}"))
    risk = RiskTier.HIGH if verdict is not Verdict.ALLOW else RiskTier.LOW
    decision = TrustEngine(code=code).decide(
        TrustContext(payload=request.get("payload", ""), risk=risk))

    # 4. Verification: emit a signed, chained attestation of the whole decision.
    log.attest(actor=principal.id, action="ai.request",
               subject=request.get("id", "req"), decision=decision.verdict.value,
               policy_rule=outcome.matched_rule or "default", reason=decision.explanation)
    return outcome, decision


def test_secret_data_routes_local_and_is_attested():
    reg, log, policy = IdentityRegistry(), AttestationLog(), parse_policy(POLICY)
    agent = reg.register("agent", display="assistant")

    outcome, decision = _pipeline(reg, log, policy, principal=agent,
                                  request={"id": "r1", "classification": "secret",
                                           "payload": "ssn 123-45-6789"})
    assert outcome.action == "route" and outcome.target == "local"
    assert decision.verdict is Verdict.QUARANTINE  # isolated from cloud

    ok, n = log.verify_chain()
    assert ok and n == 1


def test_low_trust_destination_blocked():
    reg, log, policy = IdentityRegistry(), AttestationLog(), parse_policy(POLICY)
    svc = reg.register("service")
    outcome, decision = _pipeline(reg, log, policy, principal=svc,
                                  request={"id": "r2", "dest_trust": 30})
    assert outcome.action == "block"
    assert decision.verdict is Verdict.BLOCK


def test_clean_request_allowed_and_chain_grows():
    reg, log, policy = IdentityRegistry(), AttestationLog(), parse_policy(POLICY)
    human = reg.register("human")
    for i in range(3):
        outcome, decision = _pipeline(reg, log, policy, principal=human,
                                      request={"id": f"r{i}", "dest_trust": 99})
        assert decision.verdict is Verdict.ALLOW

    ok, n = log.verify_chain()
    assert ok and n == 3  # every request left a verifiable attestation


def test_destructive_action_requires_approval():
    reg, log, policy = IdentityRegistry(), AttestationLog(), parse_policy(POLICY)
    agent = reg.register("agent")
    outcome, decision = _pipeline(reg, log, policy, principal=agent,
                                  request={"id": "r3", "action": "destructive"})
    assert outcome.action == "require_approval"
    assert decision.verdict is Verdict.ESCALATE
