"""
Tests for the TSM Trust Fabric primitives: crypto, Identity, Policy DSL,
Verification. These are the substrate every other engine consumes, so they are
exercised hard — including tamper, expiry, forgery, and parser edge cases.
"""
import time

import pytest

from tsm.fabric import (
    AttestationLog,
    HmacSigner,
    IdentityKind,
    IdentityRegistry,
    PolicyParseError,
    new_secret,
    parse_policy,
    sign_token,
    verify_token,
)


# ── crypto ────────────────────────────────────────────────────────────────────

def test_token_roundtrip():
    s = HmacSigner(b"secret-key")
    tok = sign_token({"sub": "alice", "exp": time.time() + 100}, s)
    payload = verify_token(tok, s)
    assert payload and payload["sub"] == "alice"


def test_token_tamper_detected():
    s = HmacSigner(b"k")
    tok = sign_token({"sub": "alice"}, s)
    head, body, sig = tok.split(".")
    forged = f"{head}.{body}.{'A' * len(sig)}"
    assert verify_token(forged, s) is None


def test_token_wrong_key_rejected():
    tok = sign_token({"sub": "x"}, HmacSigner(b"key-a"))
    assert verify_token(tok, HmacSigner(b"key-b")) is None


def test_token_expiry_enforced():
    s = HmacSigner()
    tok = sign_token({"sub": "x", "exp": 1000.0}, s)
    assert verify_token(tok, s, now=2000.0) is None
    assert verify_token(tok, s, now=500.0)["sub"] == "x"


def test_malformed_token_is_none():
    assert verify_token("not.a.token", HmacSigner()) is None
    assert verify_token("garbage", HmacSigner()) is None


# ── identity ──────────────────────────────────────────────────────────────────

def test_register_assigns_default_trust_by_kind():
    reg = IdentityRegistry()
    human = reg.register(IdentityKind.HUMAN)
    agent = reg.register(IdentityKind.AGENT)
    assert human.trust_score == 70.0
    assert agent.trust_score == 40.0  # agents least trusted by default


def test_session_issue_and_verify():
    reg = IdentityRegistry()
    p = reg.register("service", display="billing")
    tok = reg.issue_session(p.id, scopes=("read", "write"))
    info = reg.verify_session(tok)
    assert info is not None
    assert info.principal.id == p.id
    assert info.scopes == ("read", "write")


def test_expired_session_rejected():
    reg = IdentityRegistry()
    p = reg.register("agent")
    tok = reg.issue_session(p.id, ttl=1.0)
    assert reg.verify_session(tok, now=time.time() + 10) is None


def test_session_from_other_registry_rejected():
    a, b = IdentityRegistry(), IdentityRegistry()
    p = a.register("model")
    tok = a.issue_session(p.id)
    assert b.verify_session(tok) is None  # different signing key


def test_unknown_principal_session_rejected():
    reg = IdentityRegistry(signer=HmacSigner(b"shared"))
    # craft a validly-signed token for a principal the registry doesn't know
    tok = sign_token({"sub": "ghost", "exp": time.time() + 100}, HmacSigner(b"shared"))
    assert reg.verify_session(tok) is None


def test_adjust_trust_clamps():
    reg = IdentityRegistry()
    p = reg.register("device", trust_score=50)
    assert reg.adjust_trust(p.id, +80, "passed attestation").trust_score == 100.0
    assert reg.adjust_trust(p.id, -250, "violation").trust_score == 0.0


# ── policy DSL (the trust language) ───────────────────────────────────────────

def test_dsl_user_examples_parse_and_evaluate():
    prog = parse_policy(
        """
        # the exact examples from the spec
        when data.classification == "secret" then route local
        when destination.trust < 80 then block
        when action == "destructive" then require_approval
        default allow
        """
    )
    o1 = prog.evaluate({"data": {"classification": "secret"}})
    assert o1.action == "route" and o1.target == "local"

    o2 = prog.evaluate({"destination": {"trust": 50}})
    assert o2.action == "block"

    o3 = prog.evaluate({"action": "destructive"})
    assert o3.action == "require_approval"

    o4 = prog.evaluate({"action": "read", "destination": {"trust": 95}})
    assert o4.action == "allow" and o4.matched_rule is None  # default


def test_dsl_first_match_wins():
    prog = parse_policy(
        """
        when risk >= 50 then escalate
        when risk >= 90 then block
        """
    )
    assert prog.evaluate({"risk": 95}).action == "escalate"  # first rule wins


def test_dsl_and_or_not_and_parens():
    prog = parse_policy(
        'when identity.kind == "agent" and (risk >= 70 or flagged) then quarantine'
    )
    assert prog.evaluate({"identity": {"kind": "agent"}, "risk": 80}).action == "quarantine"
    assert prog.evaluate({"identity": {"kind": "agent"}, "flagged": True}).action == "quarantine"
    assert prog.evaluate({"identity": {"kind": "agent"}, "risk": 10}).action == "allow"
    assert prog.evaluate({"identity": {"kind": "human"}, "risk": 99}).action == "allow"


def test_dsl_in_operator():
    prog = parse_policy('when action in blocked then block')
    assert prog.evaluate({"action": "delete", "blocked": ["delete", "drop"]}).action == "block"
    assert prog.evaluate({"action": "read", "blocked": ["delete"]}).action == "allow"


def test_dsl_bare_truthy():
    prog = parse_policy("when quarantined then block")
    assert prog.evaluate({"quarantined": True}).action == "block"
    assert prog.evaluate({"quarantined": False}).action == "allow"
    assert prog.evaluate({}).action == "allow"  # missing -> falsey


def test_dsl_not_operator():
    prog = parse_policy('when not verified then escalate')
    assert prog.evaluate({"verified": False}).action == "escalate"
    assert prog.evaluate({"verified": True}).action == "allow"


def test_dsl_default_deny_configurable():
    prog = parse_policy(
        """
        when destination.trust >= 80 then allow
        default block
        """
    )
    assert prog.evaluate({"destination": {"trust": 90}}).action == "allow"
    assert prog.evaluate({"destination": {"trust": 10}}).action == "block"


def test_dsl_missing_field_is_safe():
    prog = parse_policy("when destination.trust < 80 then block")
    # 'destination' absent -> comparison is False -> falls through to default
    assert prog.evaluate({}).action == "allow"


@pytest.mark.parametrize("src", [
    "block",                       # no 'when'
    "when then block",             # empty condition
    "when risk >= 50",             # no 'then'
    "when risk >= 50 then teleport",  # unknown action
    "when risk >= then block",     # missing operand
    "when route then route",       # 'route' needs a destination
])
def test_dsl_parse_errors(src):
    with pytest.raises(PolicyParseError):
        parse_policy(src)


def test_dsl_string_equality_is_case_sensitive():
    prog = parse_policy('when env == "prod" then require_approval')
    assert prog.evaluate({"env": "prod"}).action == "require_approval"
    assert prog.evaluate({"env": "PROD"}).action == "allow"


# ── verification (attestations) ───────────────────────────────────────────────

def test_attestation_records_who_what_why():
    log = AttestationLog()
    a = log.attest(actor="agent:42", action="ai.request", subject="req-1",
                   decision="block", policy_rule="safety-veto:block",
                   reason="critical secret detected")
    assert a.actor == "agent:42"
    assert a.decision == "block"
    assert a.policy_rule == "safety-veto:block"
    assert a.seq == 0


def test_attestation_chain_links_and_verifies():
    log = AttestationLog()
    for i in range(5):
        log.attest(actor=f"svc:{i}", action="route", decision="allow")
    ok, count = log.verify_chain()
    assert ok is True
    assert count == 5
    # each links to the previous
    entries = log.entries
    for i in range(1, len(entries)):
        assert entries[i].prev_hash == entries[i - 1].hash


def test_attestation_tamper_breaks_chain():
    log = AttestationLog()
    log.attest(actor="a", action="x", decision="allow")
    log.attest(actor="b", action="y", decision="block", reason="bad")
    # tamper with a stored entry's decision
    import dataclasses
    log._entries[1] = dataclasses.replace(log._entries[1], decision="allow")
    ok, idx = log.verify_chain()
    assert ok is False
    assert idx == 1


def test_attestation_forged_signature_detected():
    log = AttestationLog()
    log.attest(actor="a", action="x", decision="allow")
    import dataclasses
    log._entries[0] = dataclasses.replace(log._entries[0], sig="AAAA")
    ok, idx = log.verify_chain()
    assert ok is False and idx == 0


def test_attestation_log_is_serializable():
    import json
    log = AttestationLog()
    a = log.attest(actor="a", action="ai.request", decision="allow", reason="clean")
    assert json.dumps(a.as_dict())  # round-trips to JSON
