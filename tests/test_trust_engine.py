"""
Tests for the Autonomous Trust Engine — the AI -> Code -> Human triple fail-safe.

Covers the architecture's stated guarantees:
  * graceful degradation (Scenarios A/B/C/D),
  * fail-safe / fail-closed bias under uncertainty,
  * safety veto + human authority,
  * high-risk quorum gate,
  * per-layer crash isolation (one layer dying never crashes the loop),
  * determinism and audit-sink safety.
"""
import json

import pytest

from tsm.engine import (
    CallableSource,
    Layer,
    LayerReport,
    LayerStatus,
    Mode,
    RiskTier,
    TrustContext,
    TrustEngine,
    Verdict,
    derive_risk,
)


# ── helpers ───────────────────────────────────────────────────────────────────

def const(layer, verdict, confidence=1.0, reason=""):
    """A layer source that always returns the same verdict."""
    return CallableSource(layer, lambda ctx: (verdict, confidence, reason))


def engine(ai=None, code=None, human=None, **kw):
    return TrustEngine(ai=ai, code=code, human=human, **kw)


LOW = TrustContext(payload="hello", risk=RiskTier.LOW)
HIGH = TrustContext(payload="secret", risk=RiskTier.HIGH)
CRIT = TrustContext(payload="ssn", risk=RiskTier.CRITICAL)


# ── 0. fail-closed when blind ─────────────────────────────────────────────────

def test_all_offline_fails_closed():
    d = engine().decide(LOW)
    assert d.verdict is Verdict.BLOCK
    assert d.mode is Mode.MINIMAL
    assert d.rule == "no-online-layers:fail-closed"
    assert d.participating == ()


def test_single_layer_abstains_is_fail_closed():
    d = engine(code=const(Layer.CODE, Verdict.ABSTAIN)).decide(LOW)
    assert d.verdict is Verdict.BLOCK  # abstain == not participating == blind


# ── Scenario D: all three online (FULL, cross-check) ──────────────────────────

def test_full_consensus_allow():
    d = engine(
        ai=const(Layer.AI, Verdict.ALLOW),
        code=const(Layer.CODE, Verdict.ALLOW),
        human=const(Layer.HUMAN, Verdict.ALLOW),
    ).decide(LOW)
    assert d.verdict is Verdict.ALLOW
    assert d.mode is Mode.FULL
    assert d.consensus is True
    assert d.autonomous is False
    assert set(d.participating) == {Layer.AI, Layer.CODE, Layer.HUMAN}


def test_full_human_overrides_machine_block():
    # AI + Code want to block; the human explicitly allows -> human authority wins.
    d = engine(
        ai=const(Layer.AI, Verdict.BLOCK),
        code=const(Layer.CODE, Verdict.BLOCK),
        human=const(Layer.HUMAN, Verdict.ALLOW),
    ).decide(HIGH)
    assert d.verdict is Verdict.ALLOW
    assert d.rule == "human-override"
    assert d.autonomous is False
    assert d.divergences  # disagreement was recorded


def test_full_human_blocks_machine_allow():
    d = engine(
        ai=const(Layer.AI, Verdict.ALLOW),
        code=const(Layer.CODE, Verdict.ALLOW),
        human=const(Layer.HUMAN, Verdict.BLOCK),
    ).decide(LOW)
    assert d.verdict is Verdict.BLOCK
    assert d.rule == "human-override"


# ── safety veto: each layer is a fail-safe for the others ─────────────────────

def test_code_block_vetoes_ai_allow():
    d = engine(
        ai=const(Layer.AI, Verdict.ALLOW),
        code=const(Layer.CODE, Verdict.BLOCK),
    ).decide(LOW)
    assert d.verdict is Verdict.BLOCK
    assert d.rule == "safety-veto:block"


def test_ai_block_vetoes_code_allow():
    d = engine(
        ai=const(Layer.AI, Verdict.BLOCK),
        code=const(Layer.CODE, Verdict.ALLOW),
    ).decide(LOW)
    assert d.verdict is Verdict.BLOCK


def test_quarantine_veto():
    d = engine(
        ai=const(Layer.AI, Verdict.ALLOW),
        code=const(Layer.CODE, Verdict.QUARANTINE),
    ).decide(LOW)
    assert d.verdict is Verdict.QUARANTINE
    assert d.rule == "safety-veto:quarantine"


def test_block_beats_quarantine():
    d = engine(
        ai=const(Layer.AI, Verdict.QUARANTINE),
        code=const(Layer.CODE, Verdict.BLOCK),
    ).decide(LOW)
    assert d.verdict is Verdict.BLOCK  # most restrictive wins


# ── Scenario A: AI offline (Code + Human) ─────────────────────────────────────

def test_scenario_a_ai_offline():
    d = engine(
        code=const(Layer.CODE, Verdict.ALLOW),
        human=const(Layer.HUMAN, Verdict.ALLOW),
    ).decide(LOW)
    assert d.verdict is Verdict.ALLOW
    assert d.mode is Mode.DEGRADED
    assert Layer.AI not in d.participating


# ── Scenario B: Code offline (AI advisory + Human) ────────────────────────────

def test_scenario_b_code_offline_human_allows():
    d = engine(
        ai=const(Layer.AI, Verdict.ALLOW),
        human=const(Layer.HUMAN, Verdict.ALLOW),
    ).decide(HIGH)
    assert d.verdict is Verdict.ALLOW
    assert d.rule == "human-authority"
    assert d.mode is Mode.DEGRADED


def test_scenario_b_ai_alone_cannot_allow_high_risk():
    # Code + Human offline; AI advisory only. High-risk ALLOW must escalate.
    d = engine(ai=const(Layer.AI, Verdict.ALLOW)).decide(HIGH)
    assert d.verdict is Verdict.ESCALATE
    assert d.rule == "high-risk-no-quorum:escalate"
    assert d.mode is Mode.MINIMAL


def test_scenario_b_ai_alone_allows_low_risk():
    d = engine(ai=const(Layer.AI, Verdict.ALLOW)).decide(LOW)
    assert d.verdict is Verdict.ALLOW
    assert d.rule == "ai-autonomous:allow"
    assert d.autonomous is True


# ── Scenario C: Human unavailable (AI + Code autonomous) ──────────────────────

def test_scenario_c_autonomous_low_risk_allows():
    d = engine(
        ai=const(Layer.AI, Verdict.ALLOW),
        code=const(Layer.CODE, Verdict.ALLOW),
    ).decide(LOW)
    assert d.verdict is Verdict.ALLOW
    assert d.mode is Mode.AUTONOMOUS
    assert d.rule == "multi-layer-consensus:allow"
    assert d.autonomous is True


def test_scenario_c_autonomous_high_risk_needs_consensus():
    # AI+Code both allow -> high-risk consensus permitted autonomously.
    d = engine(
        ai=const(Layer.AI, Verdict.ALLOW),
        code=const(Layer.CODE, Verdict.ALLOW),
    ).decide(CRIT)
    assert d.verdict is Verdict.ALLOW
    assert d.rule == "code+ai-consensus:high-risk"


def test_scenario_c_autonomous_high_risk_divergence_escalates():
    # Code allows, AI wants review -> escalate (no human, no consensus).
    d = engine(
        ai=const(Layer.AI, Verdict.ESCALATE),
        code=const(Layer.CODE, Verdict.ALLOW),
    ).decide(HIGH)
    assert d.verdict is Verdict.ESCALATE
    assert d.rule == "escalation-requested"


# ── escalation + risk auto-raise ──────────────────────────────────────────────

def test_layer_can_request_escalation():
    d = engine(
        ai=const(Layer.AI, Verdict.ESCALATE),
        code=const(Layer.CODE, Verdict.ALLOW),
    ).decide(LOW)
    assert d.verdict is Verdict.ESCALATE
    assert d.rule == "escalation-requested"


def test_restrictive_signal_raises_effective_risk():
    # A quarantine signal raises risk to HIGH even though the call came in LOW.
    d = engine(
        ai=const(Layer.AI, Verdict.QUARANTINE),
        code=const(Layer.CODE, Verdict.ALLOW),
    ).decide(LOW)
    assert d.risk is RiskTier.HIGH
    assert d.verdict is Verdict.QUARANTINE


# ── autonomous-disabled deployments ───────────────────────────────────────────

def test_autonomous_disabled_holds_for_human():
    d = engine(
        ai=const(Layer.AI, Verdict.ALLOW),
        code=const(Layer.CODE, Verdict.ALLOW),
        autonomous=False,
    ).decide(LOW)
    assert d.verdict is Verdict.ESCALATE
    assert d.rule == "autonomous-disabled:escalate"


def test_autonomous_disabled_still_allows_with_human():
    d = engine(
        ai=const(Layer.AI, Verdict.ALLOW),
        code=const(Layer.CODE, Verdict.ALLOW),
        human=const(Layer.HUMAN, Verdict.ALLOW),
        autonomous=False,
    ).decide(LOW)
    assert d.verdict is Verdict.ALLOW
    assert d.rule == "human-authority"


# ── per-layer crash isolation ─────────────────────────────────────────────────

def test_one_layer_crashing_does_not_crash_engine():
    def boom(ctx):
        raise RuntimeError("layer exploded")

    d = engine(
        ai=CallableSource(Layer.AI, boom),
        code=const(Layer.CODE, Verdict.ALLOW),
    ).decide(LOW)
    assert d.verdict is Verdict.ALLOW  # survived on Code alone
    ai_report = next(r for r in d.reports if r.layer is Layer.AI)
    assert ai_report.status is LayerStatus.OFFLINE
    assert "source error" in ai_report.reason


def test_crashing_layer_excluded_but_block_still_holds():
    def boom(ctx):
        raise ValueError("nope")

    d = engine(
        ai=CallableSource(Layer.AI, boom),
        code=const(Layer.CODE, Verdict.BLOCK),
    ).decide(LOW)
    assert d.verdict is Verdict.BLOCK


# ── adapter coercion ──────────────────────────────────────────────────────────

def test_source_may_return_bare_verdict():
    d = engine(code=CallableSource(Layer.CODE, lambda ctx: Verdict.ALLOW)).decide(LOW)
    assert d.verdict is Verdict.ALLOW


def test_source_may_return_verdict_string():
    d = engine(code=CallableSource(Layer.CODE, lambda ctx: "block")).decide(LOW)
    assert d.verdict is Verdict.BLOCK


def test_source_may_return_none_as_abstain():
    d = engine(
        code=CallableSource(Layer.CODE, lambda ctx: None),
        ai=const(Layer.AI, Verdict.ALLOW),
    ).decide(LOW)
    # code abstained -> only AI participates
    assert Layer.CODE not in d.participating
    assert d.verdict is Verdict.ALLOW


def test_low_confidence_marks_degraded():
    src = CallableSource(Layer.AI, lambda ctx: (Verdict.ALLOW, 0.2, "unsure"))
    d = engine(ai=src, code=const(Layer.CODE, Verdict.ALLOW)).decide(LOW)
    ai_report = next(r for r in d.reports if r.layer is Layer.AI)
    assert ai_report.status is LayerStatus.DEGRADED
    assert ai_report.participating is True  # degraded still counts


# ── determinism + audit + serialization ───────────────────────────────────────

def test_decision_is_deterministic():
    eng = engine(
        ai=const(Layer.AI, Verdict.ALLOW),
        code=const(Layer.CODE, Verdict.QUARANTINE),
        human=const(Layer.HUMAN, Verdict.ESCALATE),
    )
    a = eng.decide(HIGH)
    b = eng.decide(HIGH)
    assert a.verdict is b.verdict and a.rule == b.rule and a.mode is b.mode


def test_audit_sink_receives_decision():
    seen = []
    eng = engine(code=const(Layer.CODE, Verdict.ALLOW), audit=seen.append)
    eng.decide(LOW)
    assert len(seen) == 1
    assert seen[0]["verdict"] == "allow"


def test_audit_failure_never_breaks_decision():
    def bad_audit(record):
        raise RuntimeError("disk full")

    d = engine(code=const(Layer.CODE, Verdict.ALLOW), audit=bad_audit).decide(LOW)
    assert d.verdict is Verdict.ALLOW  # audit blew up, decision survived


def test_decision_as_dict_is_json_serializable():
    d = engine(
        ai=const(Layer.AI, Verdict.ALLOW),
        code=const(Layer.CODE, Verdict.BLOCK),
    ).decide(HIGH)
    blob = json.dumps(d.as_dict())
    assert "safety-veto:block" in blob


# ── derive_risk helper ────────────────────────────────────────────────────────

@pytest.mark.parametrize("severity,score,expected", [
    ("CRITICAL", None, RiskTier.CRITICAL),
    ("HIGH", None, RiskTier.HIGH),
    ("MEDIUM", None, RiskTier.MEDIUM),
    (None, 95, RiskTier.CRITICAL),
    (None, 75, RiskTier.HIGH),
    (None, 50, RiskTier.MEDIUM),
    (None, 10, RiskTier.LOW),
    (None, None, RiskTier.LOW),
])
def test_derive_risk(severity, score, expected):
    assert derive_risk(severity, score) is expected
