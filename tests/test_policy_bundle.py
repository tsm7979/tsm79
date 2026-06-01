"""Tests for signed policy bundles + loader (control/data-plane separation)."""
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from detector.policy_bundle import (
    compile_dsl, author_and_sign, sign_bundle, verify_bundle,
    PolicyCompileError, PolicyVerifyError, SignedBundle,
)
from detector.policy_loader import PolicyLoader


DSL = {
    "workspace": "finance",
    "rules": [
        {"id": "block_secrets", "priority": 10,
         "when": {"contains_pii": ["OPENAI_KEY", "AWS_KEY", "PRIVATE_KEY"]},
         "action": "block", "reason": "credential leakage"},
        {"id": "block_known_bad", "priority": 15,
         "when": {"known_bad": True}, "action": "block"},
        {"id": "quarantine_obf", "priority": 45,
         "when": {"obfuscation_gte": 0.5}, "action": "quarantine"},
        {"id": "redact_pii", "priority": 60,
         "when": {"contains_pii": ["SSN", "CREDIT_CARD", "EMAIL"]},
         "action": "redact"},
        {"id": "allow_clean", "priority": 100, "when": {}, "action": "allow"},
    ],
}


def _key():
    return Ed25519PrivateKey.generate()


# ── Compiler ─────────────────────────────────────────────────────────────────
def test_compile_valid_dsl():
    ir = compile_dsl(DSL)
    assert ir["schema"] == "tsm.policy.ir/v1"
    assert ir["workspace"] == "finance"
    # rules frozen in priority order
    prios = [r["priority"] for r in ir["rules"]]
    assert prios == sorted(prios)


def test_compile_rejects_bad_action():
    with pytest.raises(PolicyCompileError):
        compile_dsl({"rules": [{"id": "x", "action": "nuke"}]})


def test_compile_rejects_unknown_matcher():
    with pytest.raises(PolicyCompileError):
        compile_dsl({"rules": [{"id": "x", "action": "allow",
                                "when": {"made_up_matcher": 1}}]})


def test_compile_rejects_duplicate_ids():
    with pytest.raises(PolicyCompileError):
        compile_dsl({"rules": [
            {"id": "dup", "action": "allow"},
            {"id": "dup", "action": "block"},
        ]})


def test_compile_route_local_requires_target():
    with pytest.raises(PolicyCompileError):
        compile_dsl({"rules": [{"id": "r", "action": "route_local"}]})


# ── Sign / verify ────────────────────────────────────────────────────────────
def test_sign_and_verify_roundtrip():
    k = _key()
    bundle = author_and_sign(DSL, k, version=1)
    trusted = {k.public_key().public_bytes_raw().hex()}
    ir = verify_bundle(bundle, trusted_pubkeys=trusted)
    assert ir["workspace"] == "finance"


def test_verify_rejects_untrusted_key():
    k, attacker = _key(), _key()
    bundle = author_and_sign(DSL, attacker, version=1)
    trusted = {k.public_key().public_bytes_raw().hex()}  # attacker not trusted
    with pytest.raises(PolicyVerifyError):
        verify_bundle(bundle, trusted_pubkeys=trusted)


def test_verify_rejects_tampered_ir():
    k = _key()
    bundle = author_and_sign(DSL, k, version=1)
    # tamper: flip a block rule to allow AFTER signing
    bundle.ir["rules"][0]["action"] = "allow"
    trusted = {k.public_key().public_bytes_raw().hex()}
    with pytest.raises(PolicyVerifyError):
        verify_bundle(bundle, trusted_pubkeys=trusted)


def test_verify_rejects_forged_signature():
    k = _key()
    bundle = author_and_sign(DSL, k, version=1)
    forged = SignedBundle(
        ir=bundle.ir, ir_sha256=bundle.ir_sha256, pubkey=bundle.pubkey,
        signature="00" * 64, issued_at=bundle.issued_at, version=bundle.version,
    )
    trusted = {k.public_key().public_bytes_raw().hex()}
    with pytest.raises(PolicyVerifyError):
        verify_bundle(forged, trusted_pubkeys=trusted)


def test_bundle_json_roundtrip():
    k = _key()
    b = author_and_sign(DSL, k, version=3)
    b2 = SignedBundle.from_json(b.to_json())
    assert b2.version == 3 and b2.pubkey == b.pubkey
    trusted = {k.public_key().public_bytes_raw().hex()}
    assert verify_bundle(b2, trusted_pubkeys=trusted)["workspace"] == "finance"


# ── Loader (data-plane side) ─────────────────────────────────────────────────
def test_loader_accepts_signed_bundle():
    k = _key()
    loader = PolicyLoader({k.public_key().public_bytes_raw().hex()})
    res = loader.load(author_and_sign(DSL, k, version=1))
    assert res.accepted and res.rule_count == 5


def test_loader_rejects_untrusted_keeps_lkg():
    k, attacker = _key(), _key()
    loader = PolicyLoader({k.public_key().public_bytes_raw().hex()})
    # load a good v1 first
    loader.load(author_and_sign(DSL, k, version=1))
    # attacker pushes v2 -> rejected, v1 stays active (last-known-good)
    res = loader.load(author_and_sign(DSL, attacker, version=2))
    assert not res.accepted
    assert loader.active_version == 1


def test_loader_anti_rollback():
    k = _key()
    loader = PolicyLoader({k.public_key().public_bytes_raw().hex()})
    loader.load(author_and_sign(DSL, k, version=5))
    res = loader.load(author_and_sign(DSL, k, version=3))  # older
    assert not res.accepted
    assert loader.active_version == 5


def test_loader_evaluates_first_match_wins():
    k = _key()
    loader = PolicyLoader({k.public_key().public_bytes_raw().hex()})
    loader.load(author_and_sign(DSL, k, version=1))

    # secret -> block (priority 10 beats everything)
    d = loader.evaluate_ir({"pii_types": ["OPENAI_KEY"], "severity": "critical"})
    assert d["action"] == "block" and d["rule"] == "block_secrets"

    # known-bad -> block
    d = loader.evaluate_ir({"known_bad": True})
    assert d["action"] == "block" and d["rule"] == "block_known_bad"

    # heavy obfuscation -> quarantine
    d = loader.evaluate_ir({"obfuscation": 0.7})
    assert d["action"] == "quarantine"

    # plain PII -> redact
    d = loader.evaluate_ir({"pii_types": ["EMAIL"]})
    assert d["action"] == "redact"

    # clean -> allow
    d = loader.evaluate_ir({"pii_types": [], "severity": "none"})
    assert d["action"] == "allow"


def test_loader_no_policy_fails_closed():
    loader = PolicyLoader({_key().public_key().public_bytes_raw().hex()})
    d = loader.evaluate_ir({"pii_types": ["SSN"]})
    assert d["action"] == "quarantine"  # fail-closed when no policy loaded
