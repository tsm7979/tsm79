"""
TSM Semantic Detector
=====================
Goes beyond regex patterns to catch what pattern-matching misses:

  1. Jailbreak / prompt-injection attempts
     "ignore previous instructions", "DAN mode", "pretend you have no restrictions"

  2. High-entropy secrets
     Random-looking strings (base64, hex, tokens) that don't match a known pattern
     but whose Shannon entropy signals they are machine-generated secrets.

  3. Contextual PII
     Personal information revealed through context, not just format.
     "diagnosed with diabetes", "my account number is", full name + address combos.

These detections run after the regex scan and add findings to the same ScanResult.
No external dependencies.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from tsm.detectors.pii import Severity


# ── Data types ────────────────────────────────────────────────────────────────

@dataclass
class SemanticFinding:
    type: str
    severity: Severity
    description: str
    excerpt: str          # what triggered it (first 60 chars, redacted)
    confidence: float     # 0.0–1.0


@dataclass
class SemanticResult:
    findings: List[SemanticFinding] = field(default_factory=list)

    @property
    def is_clean(self) -> bool:
        return len(self.findings) == 0

    @property
    def types(self) -> List[str]:
        return [f.type for f in self.findings]

    @property
    def worst_severity(self) -> Optional[Severity]:
        if not self.findings:
            return None
        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
        for s in order:
            if any(f.severity == s for f in self.findings):
                return s
        return None


# ── Jailbreak patterns ────────────────────────────────────────────────────────

_JAILBREAK_PATTERNS: List[Tuple[re.Pattern, float]] = [
    # Direct instruction override
    (re.compile(r"ignore\s+(all\s+)?(previous|prior|above|your)\s+(instructions?|rules?|constraints?|guidelines?)", re.I), 0.95),
    (re.compile(r"disregard\s+(all\s+)?(previous|prior|your)\s+instructions?", re.I), 0.95),
    (re.compile(r"forget\s+(everything|all)\s+(you|i)\s+(told|said|know)", re.I), 0.90),
    # Role-play escape attempts
    (re.compile(r"\bDAN\s+mode\b", re.I), 0.99),
    (re.compile(r"do\s+anything\s+now", re.I), 0.85),
    (re.compile(r"pretend\s+(you\s+)?(have\s+no|don.t\s+have|are\s+without)\s+(restrictions?|limits?|rules?|guidelines?)", re.I), 0.90),
    (re.compile(r"act\s+as\s+(if\s+you\s+(have\s+no|are|were)|an?\s+AI\s+without)", re.I), 0.80),
    (re.compile(r"you\s+are\s+now\s+(a\s+)?(?:jailbroken|unrestricted|uncensored|unfiltered)", re.I), 0.95),
    # System prompt extraction
    (re.compile(r"(repeat|print|show|output|reveal|tell me)\s+(your|the)\s+(system\s+prompt|instructions?|initial\s+prompt)", re.I), 0.85),
    (re.compile(r"what\s+(are|were)\s+your\s+(original\s+)?(instructions?|rules?|system\s+prompt)", re.I), 0.75),
    # Injection via format tricks
    (re.compile(r"---+\s*system\s*---+", re.I), 0.90),
    (re.compile(r"\[INST\]|\[/INST\]|<\|im_start\|>|<\|im_end\|>", re.I), 0.85),
]

# ── High-entropy secret detection ─────────────────────────────────────────────

# Characters we consider for entropy: alphanumeric + common token chars
_TOKEN_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=_-.")

_HIGH_ENTROPY_RE = re.compile(r"\b[A-Za-z0-9+/=_\-\.]{24,}\b")

_ENTROPY_THRESHOLD = 4.2    # bits per character — most natural language is ~4.0
_MIN_LENGTH_ENTROPY = 24    # don't flag short tokens

# Known benign high-entropy things (UUIDs, base64 image headers, etc.)
_BENIGN_PREFIX = re.compile(r"^data:image/|^[0-9a-f]{8}-[0-9a-f]{4}-|^https?://", re.I)


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


def _looks_like_secret(token: str) -> bool:
    """Return True if this token looks like a machine-generated secret."""
    if len(token) < _MIN_LENGTH_ENTROPY:
        return False
    if _BENIGN_PREFIX.match(token):
        return False
    # Must be mostly token chars
    token_char_ratio = sum(1 for c in token if c in _TOKEN_CHARS) / len(token)
    if token_char_ratio < 0.90:
        return False
    return _shannon_entropy(token) >= _ENTROPY_THRESHOLD


# ── Contextual PII patterns ───────────────────────────────────────────────────

_CONTEXTUAL_PATTERNS: List[Tuple[re.Pattern, str, Severity, float]] = [
    # Medical
    (re.compile(r"(diagnosed|diagnosis|condition|prescription|prescribed|medication|treatment)\s+(with|for)\s+\w+", re.I),
     "MEDICAL_CONTEXT", Severity.HIGH, 0.80),
    (re.compile(r"(my|patient.s|their)\s+(doctor|physician|hospital|clinic|diagnosis)", re.I),
     "MEDICAL_CONTEXT", Severity.MEDIUM, 0.65),
    # Financial account context
    (re.compile(r"(account|routing|iban|swift|sort)\s+(number|code|no\.?)\s*(is|:|=)?\s*[\d\s\-]{6,}", re.I),
     "FINANCIAL_ACCOUNT", Severity.CRITICAL, 0.90),
    (re.compile(r"(bank|checking|savings|brokerage)\s+account\s+(number|no\.?|#)", re.I),
     "FINANCIAL_ACCOUNT", Severity.HIGH, 0.75),
    # Identity context
    (re.compile(r"(my|his|her|their)\s+(full\s+)?name\s+is\s+[A-Z][a-z]+\s+[A-Z][a-z]+", re.I),
     "IDENTITY_DISCLOSURE", Severity.MEDIUM, 0.70),
    (re.compile(r"(date\s+of\s+birth|dob|born\s+on|birthday)\s*(is|:)?\s*\d{1,2}[/-]\d{1,2}[/-]\d{2,4}", re.I),
     "DATE_OF_BIRTH", Severity.HIGH, 0.85),
    # Location + identity combo
    (re.compile(r"\d{1,5}\s+[A-Z][a-z]+\s+(Street|St|Avenue|Ave|Road|Rd|Drive|Dr|Lane|Ln|Blvd|Way)\b", re.I),
     "STREET_ADDRESS", Severity.MEDIUM, 0.80),
    # Credentials in plain text
    (re.compile(r"(username|user|login)\s*(is|:)?\s*\S+\s+(password|pass|pwd)\s*(is|:)?\s*\S+", re.I),
     "CREDENTIALS_PAIR", Severity.CRITICAL, 0.95),
]


# ── Public API ────────────────────────────────────────────────────────────────

class SemanticDetector:
    """
    Semantic analysis layer on top of the regex PII scanner.

    Usage:
        detector = SemanticDetector()
        result = detector.scan(text)
        if not result.is_clean:
            print(result.types)
    """

    def scan(self, text: str) -> SemanticResult:
        findings: List[SemanticFinding] = []

        # ── 1. Jailbreak detection ─────────────────────────────
        for pattern, confidence in _JAILBREAK_PATTERNS:
            m = pattern.search(text)
            if m:
                excerpt = text[max(0, m.start()-10): m.end()+10].replace("\n", " ")[:80]
                findings.append(SemanticFinding(
                    type="JAILBREAK_ATTEMPT",
                    severity=Severity.CRITICAL,
                    description="Prompt injection / jailbreak attempt detected",
                    excerpt=excerpt,
                    confidence=confidence,
                ))
                break  # one finding per category

        # ── 2. High-entropy secrets ────────────────────────────
        seen_entropy = False
        for m in _HIGH_ENTROPY_RE.finditer(text):
            token = m.group()
            if _looks_like_secret(token) and not seen_entropy:
                findings.append(SemanticFinding(
                    type="HIGH_ENTROPY_SECRET",
                    severity=Severity.HIGH,
                    description=f"High-entropy string detected (entropy={_shannon_entropy(token):.2f} bits/char)",
                    excerpt=token[:8] + "..." + token[-4:],
                    confidence=0.75,
                ))
                seen_entropy = True

        # ── 3. Contextual PII ─────────────────────────────────
        seen_types: set = set()
        for pattern, pii_type, severity, confidence in _CONTEXTUAL_PATTERNS:
            if pii_type in seen_types:
                continue
            m = pattern.search(text)
            if m:
                excerpt = text[max(0, m.start()-5): m.end()+5].replace("\n", " ")[:80]
                findings.append(SemanticFinding(
                    type=pii_type,
                    severity=severity,
                    description=f"Contextual {pii_type.replace('_', ' ').lower()} detected",
                    excerpt=excerpt,
                    confidence=confidence,
                ))
                seen_types.add(pii_type)

        return SemanticResult(findings=findings)

    def redact(self, text: str, result: SemanticResult) -> str:
        """Redact contextual PII from text (best-effort)."""
        redacted = text
        seen_types: set = set()
        for finding in result.findings:
            if finding.type in seen_types or finding.type == "JAILBREAK_ATTEMPT":
                continue
            # For contextual patterns, find and blank the matched text
            for pattern, pii_type, _, _ in _CONTEXTUAL_PATTERNS:
                if pii_type == finding.type:
                    redacted = pattern.sub(f"[REDACTED:{pii_type}]", redacted)
                    seen_types.add(pii_type)
                    break
        return redacted
