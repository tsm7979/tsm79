"""
TSM Semantic Detector
=====================
Catches what regex misses — runs after the PII scan.

Three detection layers:
  1. Prefix heuristics  — known token prefixes (ghp_, sk-ant-, glpat-, etc.)
  2. Shannon entropy    — high-entropy strings likely to be machine secrets
  3. Jailbreak patterns — prompt injection / instruction override attempts
  4. Contextual PII     — medical, financial, identity revealed through context

Unlike the regex scanner, these detections are probabilistic.
Each finding has a confidence score (0.0–1.0).
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
    type:        str
    severity:    Severity
    description: str
    excerpt:     str      # short preview (never the full secret)
    confidence:  float    # 0.0–1.0


@dataclass
class SemanticResult:
    findings: List[SemanticFinding] = field(default_factory=list)

    @property
    def is_clean(self) -> bool:
        return len(self.findings) == 0

    @property
    def types(self) -> List[str]:
        seen = set()
        return [f.type for f in self.findings if not (f.type in seen or seen.add(f.type))]

    @property
    def worst_severity(self) -> Optional[Severity]:
        if not self.findings:
            return None
        for s in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
            if any(f.severity == s for f in self.findings):
                return s
        return None


# ── 1. Known-prefix secret detection ─────────────────────────────────────────
# These prefixes are assigned by the issuing service and are definitive
# signals — no entropy analysis needed.

_PREFIX_SECRETS: List[Tuple[re.Pattern, str, Severity, float]] = [
    # GitHub
    (re.compile(r"\bghp_[A-Za-z0-9]{36,}\b"),        "GITHUB_PAT",      Severity.HIGH, 0.99),
    (re.compile(r"\bgho_[A-Za-z0-9]{36,}\b"),         "GITHUB_OAUTH",    Severity.HIGH, 0.99),
    (re.compile(r"\bghu_[A-Za-z0-9]{36,}\b"),         "GITHUB_USER",     Severity.HIGH, 0.99),
    (re.compile(r"\bghs_[A-Za-z0-9]{36,}\b"),         "GITHUB_SERVER",   Severity.HIGH, 0.99),
    (re.compile(r"\bghr_[A-Za-z0-9]{36,}\b"),         "GITHUB_REFRESH",  Severity.HIGH, 0.99),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{82,}\b"), "GITHUB_PAT_FINE", Severity.HIGH, 0.99),
    # GitLab
    (re.compile(r"\bglpat-[A-Za-z0-9\-_]{20,}\b"),   "GITLAB_PAT",      Severity.HIGH, 0.99),
    (re.compile(r"\bgldt-[A-Za-z0-9\-_]{20,}\b"),    "GITLAB_DEPLOY",   Severity.HIGH, 0.99),
    # Stripe
    (re.compile(r"\bsk_live_[A-Za-z0-9]{24,}\b"),     "STRIPE_LIVE_KEY", Severity.CRITICAL, 0.99),
    (re.compile(r"\brk_live_[A-Za-z0-9]{24,}\b"),     "STRIPE_RESTRICT", Severity.CRITICAL, 0.99),
    (re.compile(r"\bsk_test_[A-Za-z0-9]{24,}\b"),     "STRIPE_TEST_KEY", Severity.HIGH, 0.90),
    # Twilio
    (re.compile(r"\bSK[0-9a-fA-F]{32}\b"),            "TWILIO_KEY",      Severity.HIGH, 0.90),
    # Sendgrid
    (re.compile(r"\bSG\.[A-Za-z0-9\-_]{22,}\.[A-Za-z0-9\-_]{43,}\b"), "SENDGRID_KEY", Severity.HIGH, 0.99),
    # HuggingFace
    (re.compile(r"\bhf_[A-Za-z0-9]{34,}\b"),          "HUGGINGFACE_KEY", Severity.HIGH, 0.95),
    # Anthropic — also caught by regex scanner, belt-and-suspenders here
    (re.compile(r"\bsk-ant-[A-Za-z0-9\-_]{32,}\b"),   "ANTHROPIC_KEY",   Severity.HIGH, 0.99),
    # Google service account JSON private key indicator
    (re.compile(r'"private_key"\s*:\s*"-----BEGIN'),   "GCP_PRIVATE_KEY", Severity.CRITICAL, 0.99),
]


# ── 2. Entropy-based secret detection ─────────────────────────────────────────
# Target: base64url / hex strings that are long enough to be secrets
# and have Shannon entropy above the natural-language threshold.

_ENTROPY_PATTERNS = [
    # base64url (JWT components, OAuth tokens, API secrets)
    re.compile(r"\b[A-Za-z0-9+/=_\-]{32,}\b"),
    # hex strings (SSH fingerprints, hashes used as secrets)
    re.compile(r"\b[0-9a-fA-F]{40,}\b"),
]

_ENTROPY_THRESHOLD  = 4.35   # bits/char — natural language peaks ~4.1
_ENTROPY_MIN_LEN    = 32     # shorter strings have too many false positives

# Patterns that look high-entropy but are benign
_ENTROPY_ALLOW = re.compile(
    r"^(?:"
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"  # UUID
    r"|[A-Za-z0-9+/]+=*$"                                               # pure base64 (could still be secret, checked separately)
    r")",
    re.I,
)

def _shannon(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


def _is_high_entropy_secret(token: str) -> bool:
    """Return True if this token is probably a machine-generated secret."""
    if len(token) < _ENTROPY_MIN_LEN:
        return False
    # Skip UUIDs — they're structural, not secrets
    if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-', token, re.I):
        return False
    # Must be mostly token-safe chars
    safe = sum(1 for c in token if c in
               "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-.")
    if safe / len(token) < 0.90:
        return False
    return _shannon(token) >= _ENTROPY_THRESHOLD


# ── 3. Jailbreak / prompt injection patterns ──────────────────────────────────

_JAILBREAK: List[Tuple[re.Pattern, float]] = [
    (re.compile(r"ignore\s+(all\s+)?(previous|prior|above|your)\s+(instructions?|rules?|constraints?|guidelines?)", re.I), 0.97),
    (re.compile(r"disregard\s+(all\s+)?(previous|prior|your)\s+instructions?", re.I), 0.97),
    (re.compile(r"forget\s+(everything|all)\s+(you|i)\s+(told|said|know)", re.I), 0.92),
    (re.compile(r"\bDAN\s+mode\b", re.I), 0.99),
    (re.compile(r"do\s+anything\s+now", re.I), 0.87),
    (re.compile(r"pretend\s+(you\s+)?(have\s+no|don.t\s+have|are\s+without)\s+(restrictions?|limits?|rules?|guidelines?)", re.I), 0.93),
    (re.compile(r"you\s+are\s+now\s+(a\s+)?(?:jailbroken|unrestricted|uncensored|unfiltered)", re.I), 0.97),
    (re.compile(r"(repeat|print|show|output|reveal|tell me)\s+(your|the)\s+(system\s+prompt|instructions?|initial\s+prompt)", re.I), 0.88),
    (re.compile(r"---+\s*system\s*---+", re.I), 0.93),
    (re.compile(r"\[INST\]|\[/INST\]|<\|im_start\|>|<\|im_end\|>"), 0.88),
    # Obfuscated — spaces/dots in "ignore" etc.
    (re.compile(r"i[\s.*_-]g[\s.*_-]n[\s.*_-]o[\s.*_-]r[\s.*_-]e", re.I), 0.85),
]


# ── 4. Contextual PII ─────────────────────────────────────────────────────────

_CONTEXTUAL: List[Tuple[re.Pattern, str, Severity, float]] = [
    # Medical
    (re.compile(r"(diagnosed|diagnosis|prescription|prescribed|medication|treatment)\s+(with|for)\s+\w+", re.I),
     "MEDICAL_CONTEXT", Severity.HIGH, 0.80),
    # Financial account context
    (re.compile(r"(account|routing|iban|swift|sort)\s+(number|code|no\.?)\s*(is|:|=)?\s*[\d\s\-]{6,}", re.I),
     "FINANCIAL_ACCOUNT", Severity.CRITICAL, 0.92),
    # Credentials pair (username + password in same sentence)
    (re.compile(r"(username|user|login)\s*(is|:)?\s*\S+\s.{0,20}(password|pass|pwd)\s*(is|:)?\s*\S+", re.I),
     "CREDENTIALS_PAIR", Severity.CRITICAL, 0.96),
    # Date of birth
    (re.compile(r"(date\s+of\s+birth|dob|born\s+on|birthday)\s*(is|:)?\s*\d{1,2}[/-]\d{1,2}[/-]\d{2,4}", re.I),
     "DATE_OF_BIRTH", Severity.HIGH, 0.87),
    # Street address
    (re.compile(r"\d{1,5}\s+[A-Z][a-z]+\s+(Street|St|Avenue|Ave|Road|Rd|Drive|Dr|Lane|Ln|Blvd|Way)\b", re.I),
     "STREET_ADDRESS", Severity.MEDIUM, 0.82),
]


# ── Public API ────────────────────────────────────────────────────────────────

class SemanticDetector:
    """
    Second-pass semantic analysis layer.

    Run this after PIIDetector.scan() — it catches what regex misses.
    Results are additive: combine .types from both scanners for full picture.
    """

    def scan(self, text: str) -> SemanticResult:
        findings: List[SemanticFinding] = []

        # ── 1. Known-prefix secrets ────────────────────────────
        seen_prefix_types: set = set()
        for pattern, secret_type, severity, confidence in _PREFIX_SECRETS:
            if secret_type in seen_prefix_types:
                continue
            m = pattern.search(text)
            if m:
                val = m.group()
                excerpt = val[:6] + "..." + val[-4:] if len(val) > 12 else val[:4] + "..."
                findings.append(SemanticFinding(
                    type=secret_type,
                    severity=severity,
                    description=f"Known-prefix secret detected ({secret_type})",
                    excerpt=excerpt,
                    confidence=confidence,
                ))
                seen_prefix_types.add(secret_type)

        # ── 2. High-entropy secrets ────────────────────────────
        seen_entropy = False
        for pattern in _ENTROPY_PATTERNS:
            if seen_entropy:
                break
            for m in pattern.finditer(text):
                token = m.group()
                if _is_high_entropy_secret(token) and not seen_entropy:
                    entropy_val = round(_shannon(token), 2)
                    findings.append(SemanticFinding(
                        type="HIGH_ENTROPY_SECRET",
                        severity=Severity.HIGH,
                        description=f"High-entropy string (H={entropy_val} bits/char, len={len(token)})",
                        excerpt=token[:6] + "..." + token[-4:],
                        confidence=min(0.95, 0.60 + (entropy_val - _ENTROPY_THRESHOLD) * 0.5),
                    ))
                    seen_entropy = True
                    break

        # ── 3. Jailbreak detection ─────────────────────────────
        for pattern, confidence in _JAILBREAK:
            m = pattern.search(text)
            if m:
                excerpt = text[max(0, m.start()-10): m.end()+10].replace("\n", " ")[:80]
                findings.append(SemanticFinding(
                    type="JAILBREAK_ATTEMPT",
                    severity=Severity.CRITICAL,
                    description="Prompt injection / instruction override detected",
                    excerpt=excerpt,
                    confidence=confidence,
                ))
                break  # one jailbreak finding is enough

        # ── 4. Contextual PII ──────────────────────────────────
        seen_ctx: set = set()
        for pattern, pii_type, severity, confidence in _CONTEXTUAL:
            if pii_type in seen_ctx:
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
                seen_ctx.add(pii_type)

        return SemanticResult(findings=findings)

    def redact(self, text: str, result: SemanticResult) -> str:
        """Redact contextual PII matches. Prefix/entropy tokens stay as-is
        (they're already caught by the regex scanner or flagged for routing)."""
        redacted = text
        seen: set = set()
        for finding in result.findings:
            if finding.type in seen:
                continue
            for pattern, pii_type, _, _ in _CONTEXTUAL:
                if pii_type == finding.type:
                    redacted = pattern.sub(f"[REDACTED:{pii_type}]", redacted)
                    seen.add(pii_type)
                    break
        return redacted
