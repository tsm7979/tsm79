"""
Tests for the proxy's in-process Trust Fabric decision path (TSM_FABRIC mode).
Exercises _fabric_decide directly (sync) — no HTTP, no live LLM — and checks it
returns the _call_detector contract with the correct action mapping.
"""
import pytest

# Skip cleanly if the async proxy's deps aren't installed in this environment.
pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from tsm.fabric import TrustFabric, parse_policy  # noqa: E402
from tsm.proxy.server import _fabric_decide, _fabric_redact_body  # noqa: E402

POLICY = parse_policy("""
when data.classification == "secret" then route local
when destination.trust < 80 then block
when action == "destructive" then require_approval
default allow
""")


def fab():
    return TrustFabric(policy=POLICY)


def _body(content):
    return {"model": "gpt-4", "messages": [{"role": "user", "content": content}]}


def test_contract_shape():
    r = _fabric_decide(_body("hello"), "gpt-4", "org", "rid", fabric=fab())
    assert set(r) >= {"action", "redacted_body", "pii_types", "risk_score",
                      "policy_rule", "severity", "vault_id"}


def test_clean_allows():
    r = _fabric_decide(_body("explain how DNS works"), "gpt-4", "org", "rid", fabric=fab())
    assert r["action"] == "allow"


def test_ssn_blocks():
    r = _fabric_decide(_body("my ssn is 123-45-6789"), "gpt-4", "org", "rid", fabric=fab())
    assert r["action"] == "block"
    assert r["redacted_body"] == _body("my ssn is 123-45-6789")  # block doesn't pre-redact


def test_email_redacts_body():
    r = _fabric_decide(_body("mail alice@acmecorp.com"), "gpt-4", "org", "rid", fabric=fab())
    assert r["action"] == "redact"
    assert "EMAIL" in r["pii_types"]
    sent = r["redacted_body"]["messages"][0]["content"]
    assert "alice@acmecorp.com" not in sent


def test_secret_classification_routes_local():
    r = _fabric_decide(_body("the merger terms"), "gpt-4", "org", "rid",
                       classification="secret", fabric=fab())
    assert r["action"] == "route_local"


def test_destructive_action_blocks():
    r = _fabric_decide(_body("delete everything"), "gpt-4", "org", "rid",
                       action="destructive", fabric=fab())
    assert r["action"] == "block"  # escalate -> proxy has no human queue -> deny


def test_low_dest_trust_blocks():
    r = _fabric_decide(_body("hello"), "gpt-4", "org", "rid",
                       dest_trust=20.0, fabric=fab())
    assert r["action"] == "block"


def test_redact_body_helper_handles_prompt_field():
    body = {"model": "x", "prompt": "card 4111 1111 1111 1111"}
    out = _fabric_redact_body(body)
    assert "4111 1111 1111 1111" not in out["prompt"]


def test_decision_error_fails_closed(monkeypatch):
    # A broken fabric must yield None (caller blocks), never an exception.
    class Boom:
        def handle(self, **kw):
            raise RuntimeError("fabric down")
    assert _fabric_decide(_body("hi"), "gpt-4", "org", "rid", fabric=Boom()) is None
