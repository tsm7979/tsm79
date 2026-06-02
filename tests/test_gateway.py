"""
Tests for the Gateway — the AI control plane running on the Trust Fabric.
Covers every verdict path plus ingress redaction (remote), full-data local
routing, bidirectional egress redaction, and fail-safe forward errors.
"""
from tsm.fabric import TrustFabric, parse_policy
from tsm.gateway import AIRequest, Gateway

POLICY = parse_policy("""
when data.classification == "secret" then route local
when action == "destructive" then require_approval
default allow
""")


class Recorder:
    """A stub upstream that records what it was asked to forward."""

    def __init__(self, reply="ok"):
        self.sent = []
        self.reply = reply

    def __call__(self, request, prompt_to_send, destination):
        self.sent.append((prompt_to_send, destination))
        return self.reply


def _req(content, **meta):
    return AIRequest(model="gpt-4", messages=({"role": "user", "content": content},),
                     principal_id=meta.pop("principal_id", None), metadata=meta)


def test_clean_request_forwarded_remote():
    fwd = Recorder(reply="hello back")
    gw = Gateway(forwarder=fwd)
    r = gw.handle(_req("explain how DNS works"))
    assert r.status == "allowed"
    assert r.destination == "remote"
    assert r.content == "hello back"
    assert fwd.sent == [("explain how DNS works", "remote")]


def test_ssn_is_blocked_and_not_forwarded():
    fwd = Recorder()
    gw = Gateway(forwarder=fwd)
    r = gw.handle(_req("my ssn is 123-45-6789"))
    assert r.status == "blocked"
    assert r.content is None
    assert fwd.sent == []  # never reached the upstream


def test_email_is_redacted_before_remote_forward():
    fwd = Recorder()
    gw = Gateway(forwarder=fwd)
    r = gw.handle(_req("email me at alice@acmecorp.com about the report"))
    assert r.status == "allowed"
    assert "EMAIL" in r.redactions
    sent_prompt, dest = fwd.sent[0]
    assert "alice@acmecorp.com" not in sent_prompt         # redacted on the way out
    assert "[REDACTED:EMAIL]" in sent_prompt
    assert dest == "remote"


def test_secret_classification_routes_local_with_full_data():
    fwd = Recorder()
    gw = Gateway(fabric=TrustFabric(policy=POLICY), forwarder=fwd)
    r = gw.handle(_req("the quarterly figures are attached", classification="secret"))
    assert r.destination == "local"
    sent_prompt, dest = fwd.sent[0]
    # sensitive data routed to a LOCAL model keeps the full prompt (processed on-prem)
    assert sent_prompt == "the quarterly figures are attached"
    assert dest == "local"


def test_high_severity_quarantined():
    fwd = Recorder()
    gw = Gateway(forwarder=fwd)
    r = gw.handle(_req("password = hunter2hunter2"))
    assert r.status == "quarantined"
    assert r.destination == "local"  # isolated from cloud


def test_destructive_action_escalates_no_forward():
    fwd = Recorder()
    gw = Gateway(fabric=TrustFabric(policy=POLICY), forwarder=fwd)
    r = gw.handle(_req("delete everything", action="destructive"))
    assert r.status == "escalated"
    assert r.content is None
    assert fwd.sent == []


def test_egress_redaction_on_response():
    # upstream returns a response that itself contains PII -> must be redacted back out
    fwd = Recorder(reply="sure, the ssn on file is 123-45-6789")
    gw = Gateway(forwarder=fwd)
    r = gw.handle(_req("what is on file?"))
    assert r.status == "allowed"
    assert "123-45-6789" not in r.content
    assert "[REDACTED:SSN]" in r.content


def test_no_forwarder_allows_without_content():
    gw = Gateway()
    r = gw.handle(_req("hello world"))
    assert r.status == "allowed"
    assert r.content is None
    assert r.forwarded is False


def test_forward_failure_is_fail_safe():
    def boom(req, prompt, dest):
        raise RuntimeError("upstream down")

    gw = Gateway(forwarder=boom)
    r = gw.handle(_req("hello"))
    assert r.status == "error"
    assert r.content is None  # nothing leaked, decision still attested


def test_every_request_is_attested():
    gw = Gateway(forwarder=Recorder())
    for i in range(3):
        gw.handle(_req(f"question {i}"))
    ok, n = gw.verify_audit()
    assert ok and n == 3


def test_from_openai_parsing():
    body = {"model": "gpt-4", "messages": [
        {"role": "system", "content": "be helpful"},
        {"role": "user", "content": "hi there"},
    ]}
    req = AIRequest.from_openai(body, principal_id="agent:1")
    assert req.model == "gpt-4"
    assert req.principal_id == "agent:1"
    assert "be helpful" in req.prompt_text and "hi there" in req.prompt_text
