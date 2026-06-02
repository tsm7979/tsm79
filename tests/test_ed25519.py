"""
Tests for the Ed25519 asymmetric signer.

Correctness is proven against the official RFC 8032 §7.1 known-answer test
vectors (this is the standard algorithm, not novel crypto), then the Signer
interface, third-party verification, and fabric integration are checked.
"""
import time

import pytest

from tsm.fabric import (
    AttestationLog,
    Ed25519Signer,
    Ed25519Verifier,
    IdentityRegistry,
    b64u_decode,
    sign_token,
    verify_token,
)
from tsm.fabric.ed25519 import _checkvalid, _publickey, _signature, generate_keypair

# RFC 8032 §7.1 — (secret key, public key, message, signature), all hex.
# Test 1 (empty message) and Test 3 (2-byte message) — two independent official
# known-answer vectors covering key derivation, signing, and verification.
RFC8032 = [
    ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
     "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
     "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
     "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
     "af82",
     "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
     "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
]


@pytest.mark.parametrize("sk,pk,msg,sig", RFC8032)
def test_rfc8032_known_answer_vectors(sk, pk, msg, sig):
    sk_b, pk_b = bytes.fromhex(sk), bytes.fromhex(pk)
    msg_b, sig_b = bytes.fromhex(msg), bytes.fromhex(sig)
    assert _publickey(sk_b) == pk_b                    # key derivation matches RFC
    assert _signature(msg_b, sk_b, pk_b) == sig_b      # signature matches RFC
    assert _checkvalid(sig_b, msg_b, pk_b) is True     # verification accepts it


def test_generate_keypair_matches_publickey():
    seed, pub = generate_keypair(bytes.fromhex(RFC8032[0][0]))
    assert pub == bytes.fromhex(RFC8032[0][1])


def test_sign_verify_roundtrip():
    s = Ed25519Signer()
    sig = s.sign(b"hello fabric")
    assert s.verify(b"hello fabric", sig) is True
    assert len(sig) == 64


def test_signatures_are_deterministic():
    s = Ed25519Signer(seed=bytes.fromhex(RFC8032[1][0]))
    assert s.sign(b"x") == s.sign(b"x")  # Ed25519 is deterministic by design


def test_tamper_rejected():
    s = Ed25519Signer()
    sig = bytearray(s.sign(b"data"))
    sig[0] ^= 0x01
    assert s.verify(b"data", bytes(sig)) is False
    assert s.verify(b"different", s.sign(b"data")) is False


def test_third_party_verification_with_public_key_only():
    signer = Ed25519Signer()
    verifier = Ed25519Verifier(signer.public_key)   # only the public key
    sig = signer.sign(b"audit me")
    assert verifier.verify(b"audit me", sig) is True
    assert verifier.key_id == signer.key_id
    with pytest.raises(NotImplementedError):
        verifier.sign(b"nope")                      # cannot forge


def test_wrong_public_key_rejects():
    a, b = Ed25519Signer(), Ed25519Signer()
    assert Ed25519Verifier(b.public_key).verify(b"m", a.sign(b"m")) is False


def test_token_signed_with_ed25519_verifies_with_verifier():
    signer = Ed25519Signer()
    tok = sign_token({"sub": "agent:1", "exp": time.time() + 100}, signer)
    # a relying party with only the public key can verify the session token
    assert verify_token(tok, signer.verifier()) == verify_token(tok, signer)
    assert verify_token(tok, signer.verifier())["sub"] == "agent:1"


def test_identity_registry_with_ed25519():
    reg = IdentityRegistry(signer=Ed25519Signer())
    p = reg.register("agent")
    info = reg.verify_session(reg.issue_session(p.id))
    assert info is not None and info.principal.id == p.id


def test_attestation_third_party_verifiable():
    signer = Ed25519Signer()
    log = AttestationLog(signer=signer)
    att = log.attest(actor="agent:1", action="ai.request", decision="allow")
    ok, n = log.verify_chain()
    assert ok and n == 1
    # an external auditor with only the public key can verify each attestation
    verifier = signer.verifier()
    assert verifier.verify(att.hash.encode("ascii"), b64u_decode(att.sig)) is True
