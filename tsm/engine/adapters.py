"""
TSM Engine — layer adapters
===========================
Concrete trust layers that plug into :class:`tsm.engine.TrustEngine`. They turn
the abstract AI -> Code -> Human arbiter into a running machine on real input.

  * ``code_layer``  — the deterministic spine. Runs the TSM PII/secret detector
                      (and optionally the PolicyEngine) and maps findings to a
                      verdict. Authoritative, confidence 1.0, **zero deps**.
  * ``ai_layer``    — an independent advisory signal: Shannon-entropy analysis +
                      prompt-injection heuristics. Deliberately *not* a copy of
                      the Code layer, so the two genuinely cross-check each other.
                      Pure-stdlib by default; accepts a richer classifier.
  * ``human_layer`` — pluggable human decision. Absent => the human is "offline"
                      and the engine runs autonomously (its Scenario C).

Everything here is standard library only.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from typing import Callable, Optional

from tsm.engine.trust_engine import (
    CallableSource,
    Layer,
    LayerSource,
    TrustContext,
    Verdict,
)

# Secret/identity types that must never be waved through by the deterministic spine.
_CRITICAL_SECRETS = frozenset({
    "SSN", "CREDIT_CARD", "PRIVATE_KEY", "AWS_KEY", "GITHUB_TOKEN",
    "OPENAI_KEY", "ANTHROPIC_KEY", "SLACK_TOKEN",
})

# Prompt-injection / jailbreak cues — an AI-layer concern, independent of PII.
_INJECTION = re.compile(
    r"ignore\s+(?:all\s+|the\s+)?(?:previous|prior|above)\s+(?:instructions|prompts|messages)"
    r"|disregard\s+(?:all|previous|the)"
    r"|forget\s+(?:everything|all\s+previous)"
    r"|system\s+prompt"
    r"|jailbreak|do\s+anything\s+now|developer\s+mode"
    r"|bypass\s+(?:the\s+)?(?:filter|policy|guardrail|safety|restrictions)"
    r"|reveal\s+(?:your\s+)?(?:instructions|prompt|rules)",
    re.I,
)


def shannon_entropy(text: str) -> float:
    """Shannon entropy in bits per character (0 .. ~log2(alphabet))."""
    if not text:
        return 0.0
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in Counter(text).values())


# ──────────────────────────────────────────────────────────────────────────────
# Code layer — deterministic enforcement (the spine)
# ──────────────────────────────────────────────────────────────────────────────

def code_layer(detector: Optional[object] = None,
               policy: Optional[object] = None) -> LayerSource:
    """The Code System layer: deterministic PII/secret enforcement.

    Maps detector findings (and optional PolicyEngine action) to a verdict:
      critical secret / policy-block -> BLOCK
      policy route-local             -> QUARANTINE (isolate, keep off cloud)
      high-severity PII              -> QUARANTINE
      medium/low PII                 -> ALLOW (redaction handled downstream)
      clean                          -> ALLOW
    """
    from tsm.detectors.pii import PIIDetector

    det = detector or PIIDetector()

    def assess(ctx: TrustContext):
        result = det.scan(ctx.payload)
        types = result.types

        action = None
        if policy is not None:
            try:
                worst = result.worst_severity.value if result.worst_severity else "none"
                model = ctx.metadata.get("model", "cloud")
                action = policy.evaluate(ctx.payload, types, worst, model).action
            except Exception:
                action = None  # a broken policy must not break enforcement

        secrets = [t for t in types if t in _CRITICAL_SECRETS]
        if secrets or action == "block" or result.has_critical:
            why = f"critical/secret: {', '.join(secrets or types) or 'policy-block'}"
            return (Verdict.BLOCK, 1.0, why)
        if action == "route_local":
            return (Verdict.QUARANTINE, 1.0, "policy: route-local (isolate from cloud)")
        if result.has_high:
            return (Verdict.QUARANTINE, 1.0, f"high-severity PII: {', '.join(types)}")
        if types:
            return (Verdict.ALLOW, 1.0, f"redactable PII: {', '.join(types)}")
        return (Verdict.ALLOW, 1.0, "clean")

    return CallableSource(Layer.CODE, assess, name="code:pii+policy")


# ──────────────────────────────────────────────────────────────────────────────
# AI layer — independent advisory signal
# ──────────────────────────────────────────────────────────────────────────────

def ai_layer(classifier: Optional[Callable[[str], object]] = None,
             *, entropy_threshold: float = 5.0) -> LayerSource:
    """The AI layer: an advisory, confidence-scored opinion.

    By default this is a zero-dependency heuristic that is *independent* of the
    Code layer's PII regexes — it reasons about prompt-injection language and
    structural randomness (Shannon entropy of packed/encoded blobs). That
    independence is the point: redundancy only adds safety when the layers can
    actually disagree.

    Pass ``classifier`` (any ``text -> {risk_score, severity, ...}`` callable,
    e.g. ``tsm`` or the detector service) to use a stronger model; on import or
    runtime failure the layer degrades to ABSTAIN (its "offline" state), which is
    exactly how the engine's Scenario B is meant to trigger.
    """
    def assess(ctx: TrustContext):
        text = ctx.payload or ""

        if classifier is not None:
            try:
                out = classifier(text)
                return _verdict_from_classifier(out)
            except Exception:
                return None  # AI offline -> abstain -> engine degrades to Code/Human

        # Zero-dependency heuristic advisor. Independent of the Code layer (it adds
        # injection + entropy signals Code does not have) but it still covers the
        # critical-secret floor — so if the Code spine is OFFLINE, the AI layer
        # alone still stops a hard secret. Redundancy only protects you if each
        # surviving layer independently covers the worst case.
        from tsm.detectors.pii import PIIDetector

        scan = PIIDetector().scan(text)
        if scan.has_critical:
            return (Verdict.BLOCK, 0.7,
                    f"advisory: critical secret detected ({', '.join(scan.types)})")

        if _INJECTION.search(text):
            return (Verdict.ESCALATE, 0.8, "possible prompt-injection / instruction-override")

        entropy = shannon_entropy(text)
        if entropy >= entropy_threshold and len(text) >= 24:
            return (Verdict.QUARANTINE, 0.55,
                    f"high entropy {entropy:.2f} bits/char (possible encoded/packed payload)")

        confidence = 0.6 if len(text) >= 8 else 0.4  # short inputs -> low confidence (degraded)
        return (Verdict.ALLOW, confidence, f"advisory clean (entropy {entropy:.2f})")

    return CallableSource(Layer.AI, assess, name="ai:heuristic")


def _verdict_from_classifier(out: object):
    """Map a classifier dict/obj ({verdict|severity|risk_score}) to an advisory."""
    def get(key, default=None):
        if isinstance(out, dict):
            return out.get(key, default)
        return getattr(out, key, default)

    verdict = get("verdict")
    if isinstance(verdict, str):
        v = verdict.lower()
        if v in ("block", "deny"):
            return (Verdict.BLOCK, 0.85, "classifier: block")
        if v in ("redact", "quarantine"):
            return (Verdict.QUARANTINE, 0.8, "classifier: contain")

    severity = (get("severity") or "").upper() if get("severity") else ""
    score = float(get("risk_score", 0) or 0)
    if severity == "CRITICAL" or score >= 90:
        return (Verdict.BLOCK, 0.85, f"classifier risk {score:.0f}")
    if severity == "HIGH" or score >= 70:
        return (Verdict.QUARANTINE, 0.75, f"classifier risk {score:.0f}")
    if score >= 40:
        return (Verdict.ESCALATE, 0.6, f"classifier risk {score:.0f}")
    return (Verdict.ALLOW, 0.7, f"classifier risk {score:.0f}")


# ──────────────────────────────────────────────────────────────────────────────
# Human layer — pluggable oversight
# ──────────────────────────────────────────────────────────────────────────────

def human_layer(decider: Optional[Callable[[TrustContext], object]] = None) -> LayerSource:
    """The Human layer. ``decider(ctx) -> Verdict | str | None``.

    Return ``None`` (or omit ``decider``) to signal the human is unavailable —
    the engine then runs autonomously on AI+Code. Return ALLOW/BLOCK/QUARANTINE
    to exercise human authority (override), or ESCALATE to defer to autonomy."""
    def assess(ctx: TrustContext):
        return decider(ctx) if decider is not None else None

    return CallableSource(Layer.HUMAN, assess, name="human")


def constant_human(verdict: Verdict) -> LayerSource:
    """A human layer that always returns the same verdict (for demos/tests)."""
    return human_layer(lambda ctx: verdict)


# ──────────────────────────────────────────────────────────────────────────────
# Convenience
# ──────────────────────────────────────────────────────────────────────────────

def default_engine(*, human: Optional[LayerSource] = None,
                   classifier: Optional[Callable[[str], object]] = None,
                   policy: Optional[object] = None,
                   autonomous: bool = True,
                   audit: Optional[Callable[[dict], None]] = None):
    """Build a ready-to-use TrustEngine wired to the real TSM layers."""
    from tsm.engine.trust_engine import TrustEngine
    return TrustEngine(
        ai=ai_layer(classifier),
        code=code_layer(policy=policy),
        human=human,
        autonomous=autonomous,
        audit=audit,
    )
