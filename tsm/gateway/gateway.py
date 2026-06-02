"""
TSM Gateway — the AI control plane, running on the Trust Fabric
==============================================================
Product 1 (AI control plane) expressed as a consumer of Product 2 (the trust
fabric). An AI request flows through :meth:`Gateway.handle`:

    request → TrustFabric.handle (Identity→Policy→Engine→Routing→Verification)
            → act on the verdict:
                block       → refuse, do not forward
                escalate    → hold for a human, do not forward
                quarantine  → route to a LOCAL destination with the FULL prompt
                              (sensitive data is processed on-prem, not redacted away)
                allow       → forward to REMOTE with PII redacted first
            → inspect the response on the way back (bidirectional membrane)

The upstream is a pluggable ``forwarder(request, prompt_to_send, destination) ->
str`` so the gateway is fully testable without a live model; a real deployment
passes a forwarder that calls OpenAI/Anthropic for ``remote`` and a local model
for ``local``. Pure standard library.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional, Tuple

from tsm.fabric import TrustFabric

# (request, prompt_to_send, destination) -> response text
Forwarder = Callable[["AIRequest", str, str], str]
# prompt -> data classification string (e.g. "secret")
Classifier = Callable[[str], str]


@dataclass(frozen=True)
class AIRequest:
    model: str
    messages: Tuple[Dict[str, str], ...] = ()
    principal_id: Optional[str] = None
    session: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def prompt_text(self) -> str:
        """All message content concatenated — what the fabric inspects."""
        return "\n".join(str(m.get("content", "")) for m in self.messages).strip()

    @classmethod
    def from_openai(cls, body: dict, *, principal_id: Optional[str] = None,
                    session: Optional[str] = None, metadata: Optional[dict] = None) -> "AIRequest":
        """Parse an OpenAI-style ``{model, messages:[{role,content}]}`` body."""
        msgs = tuple(
            {"role": str(m.get("role", "user")), "content": str(m.get("content", ""))}
            for m in body.get("messages", [])
        )
        if not msgs and body.get("prompt"):
            msgs = ({"role": "user", "content": str(body["prompt"])},)
        return cls(model=str(body.get("model", "")), messages=msgs,
                   principal_id=principal_id, session=session, metadata=dict(metadata or {}))


@dataclass(frozen=True)
class GatewayResponse:
    status: str               # allowed | blocked | quarantined | escalated | error
    verdict: str              # the fabric's final verdict
    destination: str
    content: Optional[str]    # response text (if forwarded), already egress-inspected
    redactions: Tuple[str, ...]
    attestation_id: str
    principal: Optional[str]
    reason: str

    @property
    def forwarded(self) -> bool:
        return self.content is not None

    def as_dict(self) -> dict:
        return {
            "status": self.status, "verdict": self.verdict,
            "destination": self.destination, "content": self.content,
            "redactions": list(self.redactions), "attestation_id": self.attestation_id,
            "principal": self.principal, "reason": self.reason,
        }


class Gateway:
    """Runs AI requests through the trust fabric and enforces the verdict."""

    def __init__(self, fabric: Optional[TrustFabric] = None, *,
                 forwarder: Optional[Forwarder] = None,
                 detector: Optional[object] = None,
                 classifier: Optional[Classifier] = None) -> None:
        from tsm.detectors.pii import PIIDetector
        self.fabric = fabric or TrustFabric()
        self._forward = forwarder
        self._detector = detector or PIIDetector()
        self._classify = classifier

    def handle(self, request: AIRequest) -> GatewayResponse:
        prompt = request.prompt_text
        meta = request.metadata
        classification = (self._classify(prompt) if self._classify
                          else meta.get("classification", "public"))
        dest_trust = float(meta.get("dest_trust", 100))

        result = self.fabric.handle(
            payload=prompt,
            principal_id=request.principal_id,
            session=request.session,
            action=meta.get("action", "ai.request"),
            classification=classification,
            dest_trust=dest_trust,
            subject=meta.get("subject", request.model or "ai.request"),
        )
        verdict = result.verdict

        # Refusals never forward.
        if verdict == "block":
            return self._resp("blocked", result, None, ())
        if verdict == "escalate":
            return self._resp("escalated", result, None, ())

        # allow / quarantine may forward. Redact for REMOTE; send full data LOCAL.
        scan = self._detector.scan(prompt)
        redactions = tuple(scan.types)
        to_send = scan.redacted_text if result.destination == "remote" else prompt

        content: Optional[str] = None
        if self._forward is not None:
            try:
                raw = self._forward(request, to_send, result.destination)
            except Exception as exc:
                return self._resp("error", result, None, redactions,
                                  reason=f"upstream forward failed: {exc}")
            # Egress inspection: never let PII leak back out in the response.
            content = self._detector.redact(raw) if raw else raw

        status = "quarantined" if verdict == "quarantine" else "allowed"
        return self._resp(status, result, content, redactions)

    def _resp(self, status, result, content, redactions, reason=None) -> GatewayResponse:
        return GatewayResponse(
            status=status, verdict=result.verdict, destination=result.destination,
            content=content, redactions=tuple(redactions),
            attestation_id=result.attestation_id, principal=result.principal,
            reason=reason if reason is not None else result.reason,
        )

    def verify_audit(self):
        return self.fabric.verify_audit()
