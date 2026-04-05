"""
TSM Analyze Engine
==================
Turns the trust ledger into a risk intelligence report.

Three outputs:
  1. Risk score (0–100) — how exposed is this machine's AI usage?
  2. Leak breakdown — what types, how often, how severe?
  3. Behavioral profile — which models, which hours, trend direction?

This is the data moat: every user who runs TSM builds a local
intelligence picture of their AI risk posture that gets more
accurate over time.

Usage:
    from tsm.core.analyze import RiskEngine
    engine = RiskEngine()
    report = engine.run()
    print(report.risk_score)
"""
from __future__ import annotations

import json
import math
import pathlib
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

_LEDGER_PATH = pathlib.Path.home() / ".tsm" / "ledger.jsonl"

# ── Risk scoring weights ──────────────────────────────────────────────────────
# Each PII type contributes a base risk score per occurrence.
# Weighted by: data sensitivity + regulatory exposure + replication risk

_TYPE_RISK: Dict[str, float] = {
    # Identity destruction risk — hardest to remediate
    "SSN":                  9.5,
    "CREDENTIALS_PAIR":     9.0,
    "PRIVATE_KEY":          8.8,
    # Financial — direct monetary loss
    "CREDIT_CARD":          9.2,
    "FINANCIAL_ACCOUNT":    8.5,
    # API / system access — lateral movement
    "OPENAI_KEY":           8.0,
    "AWS_KEY":              8.5,
    "JWT":                  7.5,
    "PASSWORD":             8.0,
    "HIGH_ENTROPY_SECRET":  7.0,
    # Medical — HIPAA exposure
    "MEDICAL_CONTEXT":      7.5,
    "DATE_OF_BIRTH":        6.5,
    # Identity linkage
    "PASSPORT":             7.0,
    "IDENTITY_DISCLOSURE":  5.5,
    "STREET_ADDRESS":       5.0,
    # Contact
    "EMAIL":                4.0,
    "PHONE":                4.5,
    # Network
    "IP_ADDR":              2.5,
}

_SEVERITY_MULTIPLIER = {
    "CRITICAL": 1.0,
    "HIGH":     0.8,
    "MEDIUM":   0.5,
    "LOW":      0.2,
    "none":     0.0,
}

# ── Risk grade thresholds ─────────────────────────────────────────────────────
_GRADES: List[Tuple[int, str, str]] = [
    (90, "CRITICAL",  "Severe data exposure detected — immediate action required"),
    (70, "HIGH",      "Significant PII regularly sent to AI — review your workflow"),
    (50, "ELEVATED",  "Moderate risk — some sensitive data in AI prompts"),
    (25, "LOW",       "Minor risk — occasional low-severity PII detected"),
    ( 0, "MINIMAL",   "Very low risk — mostly clean prompts"),
]


@dataclass
class LeakEntry:
    pii_type:   str
    count:      int
    risk_score: float
    prevented:  int    # how many were routed local (not sent to cloud)


@dataclass
class RiskReport:
    risk_score:       float              # 0–100
    grade:            str               # MINIMAL / LOW / ELEVATED / HIGH / CRITICAL
    grade_message:    str
    total_requests:   int
    sensitive_pct:    float             # % of requests with PII
    prevented_pct:    float             # % of PII that never reached cloud
    leaks:            List[LeakEntry]   # per-type breakdown, sorted by risk
    top_risk_type:    Optional[str]
    trend:            str               # IMPROVING / STABLE / WORSENING / INSUFFICIENT_DATA
    trend_detail:     str
    models_exposed:   Dict[str, int]    # model → count of sensitive requests
    peak_risk_hour:   Optional[int]     # hour of day (UTC) with most PII traffic
    cost_saved:       float
    ledger_entries:   int
    chain_valid:      bool
    recommendations:  List[str]


class RiskEngine:
    """Analyze the trust ledger and produce a risk intelligence report."""

    def __init__(self, path: pathlib.Path = _LEDGER_PATH) -> None:
        self._path = path

    def run(self) -> RiskReport:
        entries = self._load()
        if not entries:
            return self._empty_report()

        total       = len(entries)
        sensitive   = [e for e in entries if e.get("pii_types")]
        prevented   = [e for e in sensitive if e.get("routed_local")]

        # ── Per-type aggregation ───────────────────────────────
        type_counts:    Dict[str, int]   = defaultdict(int)
        type_prevented: Dict[str, int]   = defaultdict(int)
        model_sensitive: Dict[str, int]  = defaultdict(int)
        hour_counts:    Dict[int, int]   = defaultdict(int)
        cost_saved = 0.0

        for e in entries:
            pii = e.get("pii_types", [])
            sev = e.get("severity", "none")
            loc = e.get("routed_local", False)
            mdl = e.get("model", "unknown")
            cost_saved += e.get("cost_saved", 0.0)

            for t in pii:
                type_counts[t] += 1
                if loc:
                    type_prevented[t] += 1

            if pii:
                model_sensitive[mdl] += 1

            ts = e.get("ts", "")
            if ts:
                try:
                    h = int(ts[11:13])
                    hour_counts[h] += 1
                except Exception:
                    pass

        # ── Risk score ────────────────────────────────────────
        raw_score = 0.0
        for t, count in type_counts.items():
            base = _TYPE_RISK.get(t, 3.0)
            # Diminishing returns: log scale so 100 occurrences isn't 100× the risk of 1
            raw_score += base * (1 + math.log1p(count - 1))

        # Normalize against a "typical bad day" reference (SSN×5 + CC×3 + email×20 ≈ 70)
        reference = 9.5 * (1 + math.log1p(4)) + 9.2 * (1 + math.log1p(2)) + 4.0 * (1 + math.log1p(19))
        risk_score = min(100.0, (raw_score / reference) * 70)

        # Boost if high % of prompts are sensitive
        sensitive_pct = len(sensitive) / total if total else 0.0
        if sensitive_pct > 0.5:
            risk_score = min(100.0, risk_score * 1.2)

        risk_score = round(risk_score, 1)

        # ── Grade ─────────────────────────────────────────────
        grade, grade_message = "MINIMAL", _GRADES[-1][2]
        for threshold, g, msg in _GRADES:
            if risk_score >= threshold:
                grade, grade_message = g, msg
                break

        # ── Leak table ────────────────────────────────────────
        leaks = sorted([
            LeakEntry(
                pii_type=t,
                count=type_counts[t],
                risk_score=round(_TYPE_RISK.get(t, 3.0) * (1 + math.log1p(type_counts[t] - 1)), 2),
                prevented=type_prevented.get(t, 0),
            )
            for t in type_counts
        ], key=lambda x: -x.risk_score)

        top_risk = leaks[0].pii_type if leaks else None

        # ── Trend (compare first half vs second half) ─────────
        trend, trend_detail = self._compute_trend(entries)

        # ── Peak risk hour ────────────────────────────────────
        peak_hour = max(hour_counts, key=lambda h: hour_counts[h]) if hour_counts else None

        # ── Chain integrity ───────────────────────────────────
        from tsm.core.ledger import TrustLedger
        ledger = TrustLedger(self._path)
        chain_valid, chain_count = ledger.verify_chain()

        # ── Recommendations ───────────────────────────────────
        recs = self._recommendations(risk_score, leaks, sensitive_pct,
                                     len(prevented) / len(sensitive) if sensitive else 1.0)

        prevented_pct = round(len(prevented) / len(sensitive), 3) if sensitive else 1.0

        return RiskReport(
            risk_score=risk_score,
            grade=grade,
            grade_message=grade_message,
            total_requests=total,
            sensitive_pct=round(sensitive_pct, 3),
            prevented_pct=prevented_pct,
            leaks=leaks,
            top_risk_type=top_risk,
            trend=trend,
            trend_detail=trend_detail,
            models_exposed=dict(sorted(model_sensitive.items(), key=lambda x: -x[1])),
            peak_risk_hour=peak_hour,
            cost_saved=round(cost_saved, 6),
            ledger_entries=chain_count,
            chain_valid=chain_valid,
            recommendations=recs,
        )

    # ── Internal ──────────────────────────────────────────────────────────────

    def _load(self) -> List[Dict[str, Any]]:
        if not self._path.exists():
            return []
        entries = []
        try:
            with open(self._path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            e = json.loads(line)
                            if e.get("type") == "intercept":
                                entries.append(e)
                        except json.JSONDecodeError:
                            pass
        except OSError:
            pass
        return entries

    def _compute_trend(self, entries: List[Dict]) -> Tuple[str, str]:
        if len(entries) < 6:
            return "INSUFFICIENT_DATA", "Need more data to detect a trend"

        mid = len(entries) // 2
        first_half  = entries[:mid]
        second_half = entries[mid:]

        def sensitive_rate(chunk):
            if not chunk:
                return 0.0
            return sum(1 for e in chunk if e.get("pii_types")) / len(chunk)

        r1 = sensitive_rate(first_half)
        r2 = sensitive_rate(second_half)
        delta = r2 - r1

        if abs(delta) < 0.05:
            return "STABLE", f"Sensitive request rate holding at {r2*100:.0f}%"
        elif delta < 0:
            return "IMPROVING", f"Sensitive rate dropped {abs(delta)*100:.0f}pp — fewer risky prompts"
        else:
            return "WORSENING", f"Sensitive rate up {delta*100:.0f}pp — more PII in recent prompts"

    def _recommendations(
        self,
        score: float,
        leaks: List[LeakEntry],
        sensitive_pct: float,
        prevented_pct: float,
    ) -> List[str]:
        recs = []

        if score >= 70:
            recs.append("Set OPENAI_BASE_URL=http://localhost:8080 in your shell profile permanently")

        for leak in leaks[:2]:
            t = leak.pii_type
            if t in ("SSN", "CREDIT_CARD", "FINANCIAL_ACCOUNT"):
                recs.append(f"Eliminate {t} from AI prompts — use reference IDs instead")
            elif t in ("AWS_KEY", "OPENAI_KEY", "PASSWORD", "CREDENTIALS_PAIR"):
                recs.append(f"Rotate any {t} that appeared in prompts — treat as compromised")
            elif t in ("PRIVATE_KEY",):
                recs.append("Rotate all private keys that appeared in AI prompts immediately")
            elif t in ("EMAIL", "PHONE"):
                recs.append(f"Replace {t} in prompts with anonymized placeholders (e.g. user@example.com)")

        if prevented_pct < 0.8 and sensitive_pct > 0.2:
            recs.append("Enable GDPR/HIPAA policy: tsm policy enable GDPR")

        if not recs:
            recs.append("Risk is low — keep TSM running and check back as usage grows")

        return recs[:4]

    def _empty_report(self) -> RiskReport:
        return RiskReport(
            risk_score=0.0,
            grade="MINIMAL",
            grade_message="No data yet",
            total_requests=0,
            sensitive_pct=0.0,
            prevented_pct=1.0,
            leaks=[],
            top_risk_type=None,
            trend="INSUFFICIENT_DATA",
            trend_detail="Run tsm enable and send some AI requests first",
            models_exposed={},
            peak_risk_hour=None,
            cost_saved=0.0,
            ledger_entries=0,
            chain_valid=True,
            recommendations=["Run: tsm enable"],
        )
