"""
TSM PII Detector
================
Fast, layered PII and secret detection. Zero dependencies.

Three stages per scan:
  1. Regex match       — structural patterns (SSN, CC, API keys)
  2. Context negation  — suppress false positives when surrounded by
                         "fake", "example", "test", "placeholder", etc.
  3. Luhn validation   — credit card numbers must pass Luhn to be CRITICAL

Entropy and semantic detection live in tsm/detectors/semantic.py
and run as a separate pass after this one.
"""

from __future__ import annotations
import re
from dataclasses import dataclass
from enum import Enum
from typing import List, Tuple, Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"   # SSN, credit card, private key → force local
    HIGH     = "HIGH"       # API keys, passwords → redact + warn
    MEDIUM   = "MEDIUM"     # Email, phone → redact, allow cloud
    LOW      = "LOW"        # IPs, paths → note only


@dataclass(frozen=True)
class Detection:
    type:     str
    severity: Severity
    value:    str       # original matched value
    redacted: str       # replacement
    start:    int
    end:      int

    @property
    def preview(self) -> str:
        if len(self.value) <= 4:
            return "***"
        return self.value[:3] + "*" * (len(self.value) - 3)


# ── Context negation window ───────────────────────────────────────────────────
# If any of these words appear within N chars before or after a match,
# we downgrade or suppress the detection.

_NEGATION_WINDOW = 40   # characters to look before/after the match

_NEGATION_WORDS = re.compile(
    r"\b(?:fake|example|sample|test|dummy|placeholder|fictional|hypothetical|"
    r"redacted|sanitized|anonymized|mock|demo|xxxxx|invalid|not real|"
    r"for illustration|illustrative|like\s+\d{3}-\d{2}-\d{4})\b",
    re.I,
)

# Quoted context: "ssn: 123-45-6789" where ssn appears as a label → still flag
# But "a fake SSN such as 123-45-6789" → suppress
def _is_negated(text: str, start: int, end: int) -> bool:
    """Return True if the match context contains negating language."""
    window_start = max(0, start - _NEGATION_WINDOW)
    window_end   = min(len(text), end + _NEGATION_WINDOW)
    context = text[window_start:window_end]
    return bool(_NEGATION_WORDS.search(context))


# ── Luhn check for credit cards ───────────────────────────────────────────────

def _luhn(number: str) -> bool:
    """Return True if number passes the Luhn algorithm."""
    digits = [int(c) for c in number if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


# ── Pattern registry ─────────────────────────────────────────────────────────
# Ordered CRITICAL → LOW so the worst severity wins on overlap.
# Each entry: (name, severity, compiled_pattern, replacement, validator_fn)
# validator_fn(text, match) → bool  — None means always accept

_PATTERNS: List[Tuple[str, Severity, re.Pattern, str, Optional[object]]] = [

    # ── CRITICAL ─────────────────────────────────────────────
    ("SSN",         Severity.CRITICAL,
     re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
     "[REDACTED:SSN]", None),

    ("CREDIT_CARD", Severity.CRITICAL,
     re.compile(r"\b(?:\d{4}[\s\-]?){3}\d{4}\b"),
     "[REDACTED:CC]",
     lambda _text, m: _luhn(m.group())),   # Luhn validation

    ("PRIVATE_KEY", Severity.CRITICAL,
     re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
     "[REDACTED:PRIVATE_KEY]", None),

    # ── HIGH ─────────────────────────────────────────────────
    # AWS access keys (all prefixes)
    ("AWS_KEY",     Severity.HIGH,
     re.compile(r"(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}"),
     "[REDACTED:AWS_KEY]", None),

    # GitHub tokens (all formats)
    ("GITHUB_TOKEN", Severity.HIGH,
     re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{82,}"),
     "[REDACTED:GITHUB_TOKEN]", None),

    # OpenAI keys (classic + project-based)
    ("OPENAI_KEY",  Severity.HIGH,
     re.compile(r"sk-(?:proj-)?[A-Za-z0-9]{20,}"),
     "[REDACTED:OPENAI_KEY]", None),

    # Anthropic keys
    ("ANTHROPIC_KEY", Severity.HIGH,
     re.compile(r"sk-ant-[A-Za-z0-9\-_]{32,}"),
     "[REDACTED:ANTHROPIC_KEY]", None),

    # Generic API key assignment
    ("API_KEY",     Severity.HIGH,
     re.compile(r"(?:api[_\-]?key|apikey|api_token|access_token)\s*[:=]\s*['\"]?[\w\-]{20,}['\"]?", re.I),
     "[REDACTED:API_KEY]", None),

    # Passwords in assignment form
    ("PASSWORD",    Severity.HIGH,
     re.compile(r"(?:password|passwd|pwd|secret)\s*[:=]\s*['\"]?\S{8,}['\"]?", re.I),
     "[REDACTED:PASSWORD]", None),

    # JWTs: three base64url segments separated by dots
    ("JWT",         Severity.HIGH,
     re.compile(r"eyJ[A-Za-z0-9\-_]{10,}\.eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}"),
     "[REDACTED:JWT]", None),

    # Slack tokens
    ("SLACK_TOKEN", Severity.HIGH,
     re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}"),
     "[REDACTED:SLACK_TOKEN]", None),

    # ── MEDIUM ───────────────────────────────────────────────
    ("EMAIL",       Severity.MEDIUM,
     re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
     "[REDACTED:EMAIL]", None),

    ("PHONE",       Severity.MEDIUM,
     re.compile(r"\b(?:\+?1[\s\-]?)?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{4}\b"),
     "[REDACTED:PHONE]", None),

    ("PASSPORT",    Severity.MEDIUM,
     re.compile(r"\b[A-Z]{1,2}\d{6,9}\b"),
     "[REDACTED:PASSPORT]", None),

    # ── LOW ──────────────────────────────────────────────────
    ("IP_ADDR",     Severity.LOW,
     re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"),
     "[REDACTED:IP]", None),
]


class PIIDetector:
    """
    Detects and redacts PII from text.

    Usage:
        detector = PIIDetector()
        result = detector.scan("My SSN is 123-45-6789")
        print(result.has_critical)   # True
        print(result.redacted_text)  # "My SSN is [REDACTED:SSN]"

    Context negation:
        result = detector.scan("fake SSN like 123-45-6789")
        print(result.is_clean)       # True — negated by "fake"
    """

    def __init__(self, min_severity: Severity = Severity.LOW):
        self.min_severity = min_severity

    def scan(self, text: str) -> "ScanResult":
        detections: List[Detection] = []
        _order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
        min_idx = _order.index(self.min_severity)

        for name, severity, pattern, replacement, validator in _PATTERNS:
            if _order.index(severity) > min_idx:
                continue
            for m in pattern.finditer(text):
                # Context negation check
                if _is_negated(text, m.start(), m.end()):
                    continue
                # Optional validator (e.g. Luhn for credit cards)
                if validator is not None and not validator(text, m):
                    continue
                detections.append(Detection(
                    type=name,
                    severity=severity,
                    value=m.group(),
                    redacted=replacement,
                    start=m.start(),
                    end=m.end(),
                ))

        return ScanResult(original=text, detections=detections)

    def redact(self, text: str) -> str:
        """Redact all PII from text in one pass."""
        result = self.scan(text)
        return result.redacted_text

    def is_clean(self, text: str) -> bool:
        return self.scan(text).is_clean


@dataclass
class ScanResult:
    original:   str
    detections: List[Detection]

    @property
    def has_critical(self) -> bool:
        return any(d.severity == Severity.CRITICAL for d in self.detections)

    @property
    def has_high(self) -> bool:
        return any(d.severity == Severity.HIGH for d in self.detections)

    @property
    def is_clean(self) -> bool:
        return len(self.detections) == 0

    @property
    def redacted_text(self) -> str:
        """Apply all redactions in reverse position order to preserve offsets."""
        result = self.original
        for d in sorted(self.detections, key=lambda x: x.start, reverse=True):
            result = result[:d.start] + d.redacted + result[d.end:]
        return result

    @property
    def types(self) -> List[str]:
        return list(dict.fromkeys(d.type for d in self.detections))  # ordered, deduped

    @property
    def worst_severity(self) -> Optional[Severity]:
        if not self.detections:
            return None
        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
        for s in order:
            if any(d.severity == s for d in self.detections):
                return s
        return None


# Module-level default instance
detector = PIIDetector()
