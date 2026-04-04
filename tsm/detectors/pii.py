"""
TSM PII Detector
================
Fast, accurate PII and secret detection with zero dependencies.
"""

from __future__ import annotations
import re
from dataclasses import dataclass
from enum import Enum
from typing import List, Tuple


class Severity(str, Enum):
    CRITICAL = "CRITICAL"   # SSN, credit card, private key → force local
    HIGH     = "HIGH"       # API keys, passwords → redact + warn
    MEDIUM   = "MEDIUM"     # Email, phone → redact, allow cloud
    LOW      = "LOW"        # IPs, paths → note only


@dataclass(frozen=True)
class Detection:
    type: str
    severity: Severity
    value: str          # original matched value
    redacted: str       # what to replace it with
    start: int
    end: int

    @property
    def preview(self) -> str:
        """Safe preview: show first 3 chars + asterisks."""
        if len(self.value) <= 4:
            return "***"
        return self.value[:3] + "*" * (len(self.value) - 3)


# ─────────────────────────────────────────────────────────────
# Pattern registry — ordered by severity (CRITICAL first)
# ─────────────────────────────────────────────────────────────
_PATTERNS: List[Tuple[str, Severity, re.Pattern, str]] = [
    # (name, severity, pattern, replacement)

    # CRITICAL
    ("SSN",         Severity.CRITICAL, re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),                          "[REDACTED:SSN]"),
    ("CREDIT_CARD", Severity.CRITICAL, re.compile(r"\b(?:\d{4}[\s\-]?){3}\d{4}\b"),                   "[REDACTED:CC]"),
    ("PRIVATE_KEY", Severity.CRITICAL, re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),        "[REDACTED:PRIVATE_KEY]"),

    # HIGH
    ("AWS_KEY",     Severity.HIGH,     re.compile(r"(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}"),            "[REDACTED:AWS_KEY]"),
    ("API_KEY",     Severity.HIGH,     re.compile(r"(?:api[_\-]?key|apikey)\s*[:=]\s*[\w\-]{16,}", re.I), "[REDACTED:API_KEY]"),
    ("PASSWORD",    Severity.HIGH,     re.compile(r"(?:password|passwd|pwd)\s*[:=]\s*\S{8,}", re.I), "[REDACTED:PASSWORD]"),
    ("JWT",         Severity.HIGH,     re.compile(r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+"), "[REDACTED:JWT]"),
    ("OPENAI_KEY",  Severity.HIGH,     re.compile(r"sk-[A-Za-z0-9]{20,}"),                            "[REDACTED:OPENAI_KEY]"),

    # MEDIUM
    ("EMAIL",       Severity.MEDIUM,   re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"), "[REDACTED:EMAIL]"),
    ("PHONE",       Severity.MEDIUM,   re.compile(r"\b(?:\+?1[\s\-]?)?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{4}\b"), "[REDACTED:PHONE]"),
    ("PASSPORT",    Severity.MEDIUM,   re.compile(r"\b[A-Z]{1,2}\d{6,9}\b"),                          "[REDACTED:PASSPORT]"),

    # LOW
    ("IP_ADDR",     Severity.LOW,      re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),                   "[REDACTED:IP]"),
]


class PIIDetector:
    """
    Detects and redacts PII from text.

    Usage:
        detector = PIIDetector()
        result = detector.scan("My SSN is 123-45-6789")
        print(result.has_critical)   # True
        print(result.redacted_text)  # "My SSN is [REDACTED:SSN]"
    """

    def __init__(self, min_severity: Severity = Severity.LOW):
        self.min_severity = min_severity

    def scan(self, text: str) -> "ScanResult":
        """Scan text and return all detections."""
        detections: List[Detection] = []

        for name, severity, pattern, replacement in _PATTERNS:
            for m in pattern.finditer(text):
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
        result = text
        for _, _, pattern, replacement in _PATTERNS:
            result = pattern.sub(replacement, result)
        return result

    def is_clean(self, text: str) -> bool:
        """Return True if text contains no detectable PII."""
        return not any(p.search(text) for _, _, p, _ in _PATTERNS)


@dataclass
class ScanResult:
    original: str
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
        """Apply all redactions to original text."""
        result = self.original
        # Apply in reverse order to preserve positions
        for d in sorted(self.detections, key=lambda x: x.start, reverse=True):
            result = result[:d.start] + d.redacted + result[d.end:]
        return result

    @property
    def types(self) -> List[str]:
        return list({d.type for d in self.detections})

    @property
    def worst_severity(self) -> Severity | None:
        if not self.detections:
            return None
        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
        for s in order:
            if any(d.severity == s for d in self.detections):
                return s
        return None


# Module-level default instance
detector = PIIDetector()
