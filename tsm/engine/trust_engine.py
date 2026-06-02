"""
TSM Autonomous Trust Engine
===========================
The arbiter at the centre of the TSM79 architecture: the ``AI -> Code -> Human``
triple fail-safe.

    Humans     approve, override, investigate, define intent.
    AI         proposes, detects, adapts, scores risk.
    Code       enforces, isolates, blocks, automates  (deterministic spine).

Three independent layers, each a fail-safe for the others:

  * If one layer is **offline**, the engine degrades to the survivors and keeps
    working (it never collapses to "fail-open").
  * If all layers are **online**, they cross-check each other; disagreement on a
    consequential action escalates to a human instead of guessing.
  * Under uncertainty the engine is **fail-safe / fail-closed**: it biases toward
    the *most restrictive* verdict (BLOCK > QUARANTINE > ESCALATE > ALLOW), so a
    blind or divided system denies by default rather than letting risk through.

This is triple-modular redundancy (the pattern avionics and spacecraft use for
high-assurance control) applied to a trust boundary. It is deterministic,
explainable and pure-stdlib — **zero runtime dependencies**.

    from tsm.engine import TrustEngine, CallableSource, Layer, Verdict, TrustContext

    engine = TrustEngine(
        ai=CallableSource(Layer.AI, my_ai_assessor),
        code=CallableSource(Layer.CODE, my_policy_assessor),
        human=CallableSource(Layer.HUMAN, my_approval_queue),
    )
    decision = engine.decide(TrustContext(payload=prompt, risk=RiskTier.HIGH))
    if decision.blocked:
        ...

The engine itself decides nothing about *what* makes content risky — that is the
job of the three layers it composes. It owns only the arbitration: who is
trusted, when, and how the system stays safe as layers come and go.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional, Sequence, Tuple


# ──────────────────────────────────────────────────────────────────────────────
# Vocabulary
# ──────────────────────────────────────────────────────────────────────────────

class Layer(str, Enum):
    """The three fail-safe layers of the trust loop."""
    AI = "ai"
    CODE = "code"
    HUMAN = "human"


class Verdict(str, Enum):
    """A single layer's opinion, or the engine's resolved decision."""
    ALLOW = "allow"
    ESCALATE = "escalate"      # defer to a human / hold for review
    QUARANTINE = "quarantine"  # isolate but do not destroy
    BLOCK = "block"            # deny outright
    ABSTAIN = "abstain"        # no opinion / not participating


# Safety ordering — higher is *more restrictive*. Used so the engine can always
# fall back to the safest stance among conflicting verdicts. ABSTAIN is -1 so it
# never wins a "most restrictive" comparison.
_SAFETY_RANK = {
    Verdict.ABSTAIN: -1,
    Verdict.ALLOW: 0,
    Verdict.ESCALATE: 1,
    Verdict.QUARANTINE: 2,
    Verdict.BLOCK: 3,
}


class LayerStatus(str, Enum):
    ONLINE = "online"
    DEGRADED = "degraded"   # responding, but low-confidence / partial
    OFFLINE = "offline"     # unreachable / crashed — excluded from the vote


class RiskTier(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Mode(str, Enum):
    """How many layers participated — i.e. how much redundancy backed the call."""
    FULL = "full"             # all 3 — continuous cross-check (maximum trust)
    AUTONOMOUS = "autonomous"  # AI + Code, no human — autonomous mode
    DEGRADED = "degraded"     # exactly 2 layers, one of them human
    MINIMAL = "minimal"       # <= 1 layer — heavy fail-safe territory


_HIGH_RISK = (RiskTier.HIGH, RiskTier.CRITICAL)


# ──────────────────────────────────────────────────────────────────────────────
# Data
# ──────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class TrustContext:
    """The thing being decided. Layers read this; they do not mutate it."""
    subject: str = ""                 # id / path / action name under decision
    payload: str = ""                 # content under inspection
    action: str = "ai.request"        # category of action
    risk: RiskTier = RiskTier.LOW     # caller's risk hint (a layer may raise it)
    metadata: dict = field(default_factory=dict)


@dataclass(frozen=True)
class LayerReport:
    """One layer's response for a single decision."""
    layer: Layer
    status: LayerStatus
    verdict: Verdict
    confidence: float = 1.0
    reason: str = ""

    @property
    def participating(self) -> bool:
        return self.status is not LayerStatus.OFFLINE and self.verdict is not Verdict.ABSTAIN

    def as_dict(self) -> dict:
        return {
            "layer": self.layer.value,
            "status": self.status.value,
            "verdict": self.verdict.value,
            "confidence": round(float(self.confidence), 4),
            "reason": self.reason,
        }


@dataclass(frozen=True)
class TrustDecision:
    """The engine's resolved, explainable decision."""
    verdict: Verdict
    mode: Mode
    risk: RiskTier
    rule: str                         # which arbitration rule fired
    consensus: bool                   # did every participating layer agree?
    autonomous: bool                  # resolved without a human in the loop?
    participating: Tuple[Layer, ...]
    reports: Tuple[LayerReport, ...]
    divergences: Tuple[str, ...]      # human-readable disagreement pairs
    explanation: str
    ts: float

    @property
    def allowed(self) -> bool:
        return self.verdict is Verdict.ALLOW

    @property
    def blocked(self) -> bool:
        return self.verdict is Verdict.BLOCK

    @property
    def needs_human(self) -> bool:
        return self.verdict is Verdict.ESCALATE

    def as_dict(self) -> dict:
        return {
            "verdict": self.verdict.value,
            "mode": self.mode.value,
            "risk": self.risk.value,
            "rule": self.rule,
            "consensus": self.consensus,
            "autonomous": self.autonomous,
            "participating": [layer.value for layer in self.participating],
            "reports": [r.as_dict() for r in self.reports],
            "divergences": list(self.divergences),
            "explanation": self.explanation,
            "ts": self.ts,
        }


# ──────────────────────────────────────────────────────────────────────────────
# Layer sources
# ──────────────────────────────────────────────────────────────────────────────

# A layer function may return any of these; the engine coerces them to a
# LayerReport. Returning None / ABSTAIN means "no opinion".
LayerResult = object  # Verdict | LayerReport | (Verdict, confidence, reason) | str | None
LayerFn = Callable[[TrustContext], LayerResult]


class LayerSource:
    """Base class for a trust layer. Subclass and implement ``assess`` — or use
    :class:`CallableSource` to wrap a plain function."""

    layer: Layer

    def assess(self, ctx: TrustContext) -> LayerReport:  # pragma: no cover - abstract
        raise NotImplementedError


@dataclass
class CallableSource(LayerSource):
    """Adapt any ``ctx -> result`` callable into a trust layer.

    The callable may return a ``Verdict``, a ``LayerReport``, a
    ``(Verdict, confidence, reason)`` tuple, a verdict string, or ``None``.
    Exceptions are caught by the engine and treated as OFFLINE (per-layer
    isolation: one layer crashing can never crash the loop)."""

    layer: Layer
    fn: LayerFn
    name: str = ""

    def assess(self, ctx: TrustContext) -> LayerReport:
        return _coerce_report(self.layer, self.fn(ctx))


def _coerce_report(layer: Layer, out: LayerResult) -> LayerReport:
    if out is None:
        return LayerReport(layer, LayerStatus.OFFLINE, Verdict.ABSTAIN, 0.0, "no opinion")
    if isinstance(out, LayerReport):
        return out
    if isinstance(out, Verdict):
        status = LayerStatus.OFFLINE if out is Verdict.ABSTAIN else LayerStatus.ONLINE
        return LayerReport(layer, status, out, 1.0, "")
    if isinstance(out, str):
        return _coerce_report(layer, Verdict(out))
    if isinstance(out, (tuple, list)) and out:
        verdict = out[0] if isinstance(out[0], Verdict) else Verdict(str(out[0]))
        confidence = float(out[1]) if len(out) > 1 else 1.0
        reason = str(out[2]) if len(out) > 2 else ""
        status = LayerStatus.OFFLINE if verdict is Verdict.ABSTAIN else LayerStatus.ONLINE
        if 0.0 <= confidence < 0.5 and status is LayerStatus.ONLINE:
            status = LayerStatus.DEGRADED
        return LayerReport(layer, status, verdict, confidence, reason)
    raise TypeError(f"unsupported layer result: {type(out)!r}")


# ──────────────────────────────────────────────────────────────────────────────
# Engine
# ──────────────────────────────────────────────────────────────────────────────

class TrustEngine:
    """Arbitrates AI / Code / Human layers into one fail-safe decision.

    Parameters
    ----------
    ai, code, human : LayerSource | None
        The three layers. Any may be omitted (treated as permanently offline).
    autonomous : bool
        If False, any ALLOW that lacks a human in the loop becomes ESCALATE —
        for deployments that refuse unattended approvals. Default True.
    audit : Callable[[dict], None] | None
        Optional sink for the decision record (e.g. ``ledger.record``). Called
        defensively — an audit failure never changes or breaks the decision.
    """

    def __init__(
        self,
        ai: Optional[LayerSource] = None,
        code: Optional[LayerSource] = None,
        human: Optional[LayerSource] = None,
        *,
        autonomous: bool = True,
        audit: Optional[Callable[[dict], None]] = None,
    ) -> None:
        self._sources: dict[Layer, Optional[LayerSource]] = {
            Layer.AI: ai,
            Layer.CODE: code,
            Layer.HUMAN: human,
        }
        self._autonomous = autonomous
        self._audit = audit

    # ── public API ────────────────────────────────────────────────────────────

    def decide(self, ctx: TrustContext) -> TrustDecision:
        reports = tuple(self._safe_assess(layer, ctx) for layer in Layer)
        decision = self._arbitrate(ctx, reports)
        if self._audit is not None:
            try:
                self._audit(decision.as_dict())
            except Exception:
                pass  # audit must never break the trust decision (fail-safe)
        return decision

    # ── per-layer isolation ─────────────────────────────────────────────────────

    def _safe_assess(self, layer: Layer, ctx: TrustContext) -> LayerReport:
        src = self._sources.get(layer)
        if src is None:
            return LayerReport(layer, LayerStatus.OFFLINE, Verdict.ABSTAIN, 0.0, "not configured")
        try:
            report = src.assess(ctx)
        except Exception as exc:  # one layer failing cannot crash the engine
            return LayerReport(layer, LayerStatus.OFFLINE, Verdict.ABSTAIN, 0.0,
                               f"source error: {type(exc).__name__}: {exc}")
        if not isinstance(report, LayerReport):
            return LayerReport(layer, LayerStatus.OFFLINE, Verdict.ABSTAIN, 0.0,
                               "source returned non-report")
        # Normalise: a report whose layer mismatches is corrected, not trusted blindly.
        if report.layer is not layer:
            report = LayerReport(layer, report.status, report.verdict, report.confidence, report.reason)
        return report

    # ── arbitration (deterministic, fail-safe) ──────────────────────────────────

    def _arbitrate(self, ctx: TrustContext, reports: Tuple[LayerReport, ...]) -> TrustDecision:
        ts = time.time()
        parts = [r for r in reports if r.participating]
        part_layers = tuple(sorted({r.layer for r in parts}, key=lambda layer: layer.value))
        mode = _mode(part_layers)
        risk = self._effective_risk(ctx, parts)
        verdict_by_layer = {r.layer: r.verdict for r in parts}
        divergences = _divergences(parts)
        consensus = len(parts) >= 2 and len({r.verdict for r in parts}) == 1
        human_in_loop = Layer.HUMAN in part_layers

        def decide(verdict: Verdict, rule: str, explanation: str,
                   autonomous: Optional[bool] = None) -> TrustDecision:
            return TrustDecision(
                verdict=verdict, mode=mode, risk=risk, rule=rule,
                consensus=consensus,
                autonomous=(not human_in_loop) if autonomous is None else autonomous,
                participating=part_layers, reports=reports,
                divergences=tuple(divergences), explanation=explanation, ts=ts,
            )

        # 0. Nobody is online → fail closed. A blind boundary denies by default.
        if not parts:
            return decide(Verdict.BLOCK, "no-online-layers:fail-closed",
                          "All trust layers are offline; failing closed (deny by default).",
                          autonomous=True)

        # 1. Human authority. Humans define intent and may override the machine.
        human_verdict = verdict_by_layer.get(Layer.HUMAN)
        if human_verdict in (Verdict.ALLOW, Verdict.BLOCK, Verdict.QUARANTINE):
            overrode = any(v != human_verdict and layer is not Layer.HUMAN
                           for layer, v in verdict_by_layer.items())
            rule = "human-override" if overrode else "human-authority"
            note = " (overriding the machine layers)" if overrode else ""
            return decide(human_verdict, rule,
                          f"Human decision: {human_verdict.value}{note}.", autonomous=False)
        # human_verdict is ESCALATE or None → fall through to machine arbitration.

        # 2. Safety veto. Any participating layer can force BLOCK — each layer is a
        #    fail-safe for the others, so the safest stance wins.
        blockers = [layer.value for layer, v in verdict_by_layer.items() if v is Verdict.BLOCK]
        if blockers:
            return decide(Verdict.BLOCK, "safety-veto:block",
                          f"BLOCK demanded by: {', '.join(sorted(blockers))}.")

        # 3. Quarantine veto (next safest).
        quar = [layer.value for layer, v in verdict_by_layer.items() if v is Verdict.QUARANTINE]
        if quar:
            return decide(Verdict.QUARANTINE, "safety-veto:quarantine",
                          f"QUARANTINE demanded by: {', '.join(sorted(quar))}.")

        # 4. Anyone (incl. a human) explicitly asking for review → escalate.
        escalators = [layer.value for layer, v in verdict_by_layer.items() if v is Verdict.ESCALATE]
        if escalators:
            return decide(Verdict.ESCALATE, "escalation-requested",
                          f"Human review requested by: {', '.join(sorted(escalators))}.")

        # 5. Everything participating now says ALLOW. Gate by risk + redundancy.
        allow_layers = tuple(layer for layer, v in verdict_by_layer.items() if v is Verdict.ALLOW)

        # 5a. Autonomous approvals disabled and no human present → hold for a human.
        if not self._autonomous and not human_in_loop:
            return decide(Verdict.ESCALATE, "autonomous-disabled:escalate",
                          "Autonomous approvals are disabled; awaiting human sign-off.",
                          autonomous=False)

        # 5b. High-risk gate: a consequential ALLOW needs either a human (handled
        #     above) or AI+Code consensus. A single blind layer cannot wave it through.
        if risk in _HIGH_RISK:
            if Layer.AI in allow_layers and Layer.CODE in allow_layers:
                return decide(Verdict.ALLOW, "code+ai-consensus:high-risk",
                              "High-risk action allowed by AI+Code consensus (autonomous mode).")
            return decide(Verdict.ESCALATE, "high-risk-no-quorum:escalate",
                          "High-risk action lacks human approval and AI+Code consensus; escalating.")

        # 5c. Low/medium risk: any participating machine layer may authorise.
        if len(allow_layers) >= 2:
            rule = "multi-layer-consensus:allow"
        else:
            rule = f"{allow_layers[0].value}-autonomous:allow"
        return decide(Verdict.ALLOW, rule,
                      "Low/medium-risk action allowed by the participating layer(s).")

    # ── helpers ─────────────────────────────────────────────────────────────────

    @staticmethod
    def _effective_risk(ctx: TrustContext, parts: Sequence[LayerReport]) -> RiskTier:
        """A layer may raise (never lower) the caller's risk hint by signalling a
        restrictive verdict — uncertainty escalates risk, it never relaxes it."""
        risk = ctx.risk
        signalled = any(r.verdict in (Verdict.BLOCK, Verdict.QUARANTINE, Verdict.ESCALATE)
                        for r in parts)
        if signalled and risk not in _HIGH_RISK:
            return RiskTier.HIGH
        return risk


def _mode(part_layers: Tuple[Layer, ...]) -> Mode:
    s = set(part_layers)
    if {Layer.AI, Layer.CODE, Layer.HUMAN} <= s:
        return Mode.FULL
    if s == {Layer.AI, Layer.CODE}:
        return Mode.AUTONOMOUS
    if len(s) == 2:
        return Mode.DEGRADED
    return Mode.MINIMAL


def _divergences(parts: Sequence[LayerReport]) -> list[str]:
    """Human-readable disagreement pairs, e.g. ``ai=allow vs code=block``."""
    out: list[str] = []
    items = sorted(parts, key=lambda r: r.layer.value)
    for i in range(len(items)):
        for j in range(i + 1, len(items)):
            a, b = items[i], items[j]
            if a.verdict is not b.verdict:
                out.append(f"{a.layer.value}={a.verdict.value} vs {b.layer.value}={b.verdict.value}")
    return out


# ──────────────────────────────────────────────────────────────────────────────
# Convenience
# ──────────────────────────────────────────────────────────────────────────────

def derive_risk(severity: Optional[str] = None, risk_score: Optional[float] = None) -> RiskTier:
    """Map a TSM severity string and/or 0–100 risk score to a RiskTier."""
    sev = (severity or "").upper()
    if sev == "CRITICAL":
        return RiskTier.CRITICAL
    if sev == "HIGH":
        return RiskTier.HIGH
    if sev == "MEDIUM":
        return RiskTier.MEDIUM
    if risk_score is not None:
        if risk_score >= 90:
            return RiskTier.CRITICAL
        if risk_score >= 70:
            return RiskTier.HIGH
        if risk_score >= 40:
            return RiskTier.MEDIUM
    return RiskTier.LOW
