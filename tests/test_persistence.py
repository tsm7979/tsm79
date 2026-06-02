"""
Tests for fabric persistence — durable signer, identity registry, and the
on-disk attestation hash-chain surviving restarts (with tamper detection).
"""
from tsm.fabric import (
    AttestationLog,
    IdentityRegistry,
    persistent_signer,
    sign_token,
    verify_token,
)


# ── durable signer ────────────────────────────────────────────────────────────

def test_persistent_signer_is_stable_across_restarts(tmp_path):
    kf = str(tmp_path / "fabric.key")
    s1 = persistent_signer(kf)
    s2 = persistent_signer(kf)  # second "process" loads the same key
    assert s1.key_id == s2.key_id
    tok = sign_token({"sub": "x"}, s1)
    assert verify_token(tok, s2) == {"sub": "x"}  # cross-restart verification works


def test_persistent_signer_creates_keyfile(tmp_path):
    kf = tmp_path / "k.key"
    assert not kf.exists()
    persistent_signer(str(kf))
    assert kf.exists() and kf.read_text().strip()


# ── identity registry persistence ─────────────────────────────────────────────

def test_identity_registry_survives_restart(tmp_path):
    kf = str(tmp_path / "id.key")
    store = str(tmp_path / "principals.json")
    signer = persistent_signer(kf)

    reg1 = IdentityRegistry(signer=signer, path=store)
    agent = reg1.register("agent", display="assistant", trust_score=55)
    token = reg1.issue_session(agent.id)

    # "restart": new registry from the same files + same signer
    reg2 = IdentityRegistry(signer=persistent_signer(kf), path=store)
    loaded = reg2.get(agent.id)
    assert loaded is not None
    assert loaded.display == "assistant"
    assert loaded.trust_score == 55.0
    # a session issued before the restart still verifies after it
    info = reg2.verify_session(token)
    assert info is not None and info.principal.id == agent.id


def test_trust_adjustment_is_persisted(tmp_path):
    store = str(tmp_path / "p.json")
    signer = persistent_signer(str(tmp_path / "k.key"))
    reg = IdentityRegistry(signer=signer, path=store)
    p = reg.register("device", trust_score=50)
    reg.adjust_trust(p.id, -20, "anomaly")

    reg2 = IdentityRegistry(signer=signer, path=store)
    assert reg2.get(p.id).trust_score == 30.0


# ── attestation log persistence + tamper ──────────────────────────────────────

def test_attestation_log_survives_restart_and_chain_links(tmp_path):
    log_path = str(tmp_path / "attest.jsonl")
    signer = persistent_signer(str(tmp_path / "a.key"))

    log1 = AttestationLog(signer=signer, path=log_path)
    for i in range(3):
        log1.attest(actor=f"svc:{i}", action="route", decision="allow")

    # "restart": reload from disk with the same key
    log2 = AttestationLog(signer=persistent_signer(str(tmp_path / "a.key")), path=log_path)
    assert len(log2) == 3
    ok, n = log2.verify_chain()
    assert ok and n == 3
    # appending after restart continues the same chain
    log2.attest(actor="svc:3", action="block", decision="block")
    ok2, n2 = log2.verify_chain()
    assert ok2 and n2 == 4
    assert log2.entries[3].prev_hash == log2.entries[2].hash


def test_on_disk_tamper_is_detected_after_reload(tmp_path):
    log_path = tmp_path / "attest.jsonl"
    signer = persistent_signer(str(tmp_path / "a.key"))
    log = AttestationLog(signer=signer, path=str(log_path))
    log.attest(actor="a", action="x", decision="allow")
    log.attest(actor="b", action="y", decision="block", reason="bad")

    # tamper with the file on disk (flip a decision)
    lines = log_path.read_text(encoding="utf-8").splitlines()
    lines[1] = lines[1].replace('"decision":"block"', '"decision":"allow"')
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    reloaded = AttestationLog(signer=persistent_signer(str(tmp_path / "a.key")),
                              path=str(log_path))
    ok, idx = reloaded.verify_chain()
    assert ok is False
    assert idx == 1


def test_default_is_in_memory_no_files(tmp_path):
    # No path => nothing written to disk (back-compat).
    log = AttestationLog()
    log.attest(actor="a", action="x", decision="allow")
    reg = IdentityRegistry()
    reg.register("human")
    assert list(tmp_path.iterdir()) == []
