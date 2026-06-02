"""
Tests for the unified TrustFabric facade — all five engines + the arbiter in one
handle() call, with the most-restrictive combination rule and a verifiable audit.
"""
from tsm.fabric import Destination, IdentityRegistry, TrustFabric, parse_policy

POLICY = parse_policy("""
when data.classification == "secret" then route local
when destination.trust < 80 then block
when action == "destructive" then require_approval
default allow
""")


def _fabric():
    reg = IdentityRegistry()
    fab = TrustFabric(identity=reg, policy=POLICY)
    return reg, fab


def test_clean_request_allowed_and_routed_remote():
    reg, fab = _fabric()
    p = reg.register("human")
    r = fab.handle(payload="explain DNS", principal_id=p.id, dest_trust=99)
    assert r.verdict == "allow"
    assert r.destination == Destination.REMOTE.value
    assert r.principal == p.id


def test_secret_classification_routes_local():
    reg, fab = _fabric()
    p = reg.register("agent")
    r = fab.handle(payload="quarterly numbers", principal_id=p.id, classification="secret")
    # policy 'route local' -> allowed but destination local
    assert r.destination == Destination.LOCAL.value


def test_payload_secret_blocks_even_if_policy_allows():
    # Governance says allow (public, high trust) but the payload carries an SSN ->
    # engine BLOCK must win (most-restrictive combination).
    reg, fab = _fabric()
    p = reg.register("human")
    r = fab.handle(payload="my ssn is 123-45-6789", principal_id=p.id, dest_trust=99)
    assert r.verdict == "block"
    assert r.destination == Destination.BLOCKED.value


def test_low_trust_destination_blocked_by_policy():
    reg, fab = _fabric()
    p = reg.register("service")
    r = fab.handle(payload="hello", principal_id=p.id, dest_trust=20)
    assert r.verdict == "block"


def test_destructive_action_requires_approval_routes_human():
    reg, fab = _fabric()
    p = reg.register("agent")
    r = fab.handle(payload="rm -rf", principal_id=p.id, action="destructive")
    assert r.verdict == "escalate"
    assert r.destination == Destination.HUMAN.value


def test_every_request_is_attested_and_chain_verifies():
    reg, fab = _fabric()
    p = reg.register("human")
    for i in range(4):
        fab.handle(payload=f"q{i}", principal_id=p.id, dest_trust=99)
    ok, n = fab.verify_audit()
    assert ok and n == 4


def test_anonymous_principal_when_no_identity():
    _, fab = _fabric()
    r = fab.handle(payload="hi", dest_trust=99)
    assert r.principal is None
    # still produces a verifiable attestation
    ok, n = fab.verify_audit()
    assert ok and n == 1


def test_result_is_serializable():
    import json
    reg, fab = _fabric()
    p = reg.register("human")
    r = fab.handle(payload="ok", principal_id=p.id, dest_trust=99)
    assert json.dumps(r.as_dict())
