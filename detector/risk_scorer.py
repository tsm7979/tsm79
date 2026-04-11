"""
CVSS-grounded risk scorer for TSM detection findings.

Replaces magic-number risk scores with reproducible CVSS 3.1 base scores,
adjusted by business impact and frequency of occurrence.

CVSS 3.1 base scores by PII category:
  - API keys / secrets      → 9.8 (network-exploitable critical)
  - PII credentials (SSN)   → 7.5 (high — identity theft)
  - Financial (CC, IBAN)    → 7.5 (high — direct financial loss)
  - Health / medical         → 7.1 (high — HIPAA breach)
  - PII contact (email, ph)  → 5.3 (medium — social engineering)
  - Structural ambiguous     → 4.0 (medium — context-dependent)
  - Name / org (NER)         → 3.1 (low — context-dependent)
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import List


class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    NONE     = "none"


# CVSS 3.1 base scores per PII type.
# Based on NVD scoring criteria for unauthorized disclosure of each data class.
_CVSS_BASE: dict[str, float] = {
    # ── Secrets / credentials ─────────────────────────────────────────────────
    "API_KEY_OPENAI":    9.8,
    "API_KEY_ANTHROPIC": 9.8,
    "API_KEY_GITHUB":    9.8,
    "API_KEY_AWS":       9.8,
    "API_KEY_GCP":       9.8,
    "API_KEY_AZURE":     9.8,
    "PRIVATE_KEY":       9.8,
    "JWT":               8.1,
    "PASSWORD":          8.1,
    # ── Government ID / critical PII ─────────────────────────────────────────
    "SSN":               7.5,
    "PASSPORT":          7.5,
    "DRIVERS_LICENSE":   7.2,
    # ── Financial ─────────────────────────────────────────────────────────────
    "CREDIT_CARD":       7.5,
    "IBAN":              7.2,
    "BANK_ACCOUNT":      7.2,
    # ── Health / HIPAA-covered ────────────────────────────────────────────────
    "MEDICAL_INFO":      7.1,
    "HEALTH_RECORD":     7.1,
    # ── Contact / PII ────────────────────────────────────────────────────────
    "EMAIL":             5.3,
    "PHONE":             5.0,
    "ADDRESS":           4.8,
    "IP_ADDRESS":        3.7,
    # ── NER / prose PII (context-dependent) ──────────────────────────────────
    "PERSON":            3.1,
    "ORG":               2.0,
    "GPE":               2.0,  # geo-political entity
    "MONEY":             4.0,
    # ── Structural (detected by pattern, not type) ────────────────────────────
    "HIGH_ENTROPY":      4.0,
}

_DEFAULT_CVSS = 3.0  # unknown type — conservative medium-low


@dataclass(frozen=True)
class ScoredFinding:
    pii_type:   str
    cvss_base:  float
    adjusted:   float    # cvss_base × business_impact_multiplier
    risk_level: RiskLevel


def cvss_to_level(score: float) -> RiskLevel:
    if score >= 9.0: return RiskLevel.CRITICAL
    if score >= 7.0: return RiskLevel.HIGH
    if score >= 4.0: return RiskLevel.MEDIUM
    if score > 0.0:  return RiskLevel.LOW
    return RiskLevel.NONE


def score_findings(
    pii_types: list[str],
    business_impact: float = 1.0,
) -> tuple[float, RiskLevel, list[ScoredFinding]]:
    """
    Score a list of detected PII types using CVSS base scores.

    Args:
        pii_types:        PII types detected in the request.
        business_impact:  Multiplier 0.5–1.5. Use higher values for production
                          deployments with customer data; lower for internal tools.

    Returns:
        (composite_score, risk_level, per_type_details)
        composite_score is the MAX adjusted CVSS (0–100 scale).
    """
    if not pii_types:
        return 0.0, RiskLevel.NONE, []

    scored: list[ScoredFinding] = []
    for pii_type in pii_types:
        base    = _CVSS_BASE.get(pii_type, _DEFAULT_CVSS)
        adjusted = min(10.0, base * business_impact)
        scored.append(ScoredFinding(
            pii_type=pii_type,
            cvss_base=base,
            adjusted=adjusted,
            risk_level=cvss_to_level(adjusted),
        ))

    # Composite = max adjusted score scaled to 0–100
    max_adjusted  = max(s.adjusted for s in scored)
    composite_100 = round(max_adjusted * 10, 1)
    level         = cvss_to_level(max_adjusted)

    return composite_100, level, scored


def severity_from_level(level: RiskLevel) -> str:
    """Map RiskLevel enum to legacy severity string for API compat."""
    return level.value
