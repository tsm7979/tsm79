"""
Multi-layer classifier — the detection core.

Layers (in order):
  1. Regex + context negation   — fast, zero latency
  2. Entropy analysis            — catches obfuscated secrets
  3. Structural parsing          — JWTs, API key prefixes, JSON payloads
  4. LLM-assisted classification — called only when layers 1-3 are ambiguous
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import math
import os
import re
from dataclasses import dataclass, field
from typing import Any

# ── Shannon entropy ───────────────────────────────────────────────────────────

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())

# ── Luhn validator (credit cards) ────────────────────────────────────────────

def luhn_valid(number: str) -> bool:
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 13:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        total += d if i % 2 == 0 else (d * 2 - 9 if d * 2 > 9 else d * 2)
    return total % 10 == 0

# ── Scan result ───────────────────────────────────────────────────────────────

@dataclass
class ScanResult:
    pii_types:     list[str]      = field(default_factory=list)
    severity:      str            = "none"
    risk_score:    float          = 0.0
    redacted_text: str            = ""
    raw_findings:  list[dict]     = field(default_factory=list)
    needs_llm_assist: bool        = False
    _original_text: str           = field(default="", repr=False)

    def merge_llm(self, llm_findings: list[dict]) -> None:
        for f in llm_findings:
            if f["type"] not in self.pii_types:
                self.pii_types.append(f["type"])
                self.raw_findings.append(f)
        self._recompute_risk()

    def merge_structural(self, structural: list[dict]) -> None:
        for f in structural:
            if f["type"] not in self.pii_types:
                self.pii_types.append(f["type"])
                self.raw_findings.append(f)
        self._recompute_risk()

    def _recompute_risk(self) -> None:
        self.risk_score, self.severity = _compute_risk(self.pii_types, self.raw_findings)


# ── Regex patterns ────────────────────────────────────────────────────────────

_NEGATION_WINDOW = 40
_NEGATION_WORDS  = re.compile(
    r'\b(fake|example|dummy|sample|test|placeholder|redacted|invalid|fictional|'
    r'demo|mock|synthetic|hypothetical|not[-\s]real|censored)\b',
    re.IGNORECASE,
)

# (name, severity, pattern, validator?)
_PATTERNS: list[tuple[str, str, re.Pattern, Any]] = [
    # Secrets — always CRITICAL
    ("GITHUB_TOKEN",    "critical", re.compile(r'(ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}'), None),
    ("ANTHROPIC_KEY",   "critical", re.compile(r'sk-ant-[A-Za-z0-9\-_]{20,}'), None),
    ("OPENAI_KEY",      "critical", re.compile(r'sk-(?:proj-)?[A-Za-z0-9_\-]{20,}'), None),
    ("STRIPE_SECRET",   "critical", re.compile(r'(sk|rk)_live_[A-Za-z0-9]{20,}'), None),
    ("SENDGRID_KEY",    "critical", re.compile(r'SG\.[A-Za-z0-9\-_]{20,}'), None),
    ("HUGGINGFACE_KEY", "critical", re.compile(r'hf_[A-Za-z0-9]{20,}'), None),
    ("GITLAB_TOKEN",    "critical", re.compile(r'(glpat|gldt)-[A-Za-z0-9\-_]{20,}'), None),
    ("TWILIO_SID",      "critical", re.compile(r'SK[0-9a-f]{32}'), None),
    ("AWS_KEY",         "critical", re.compile(r'AKIA[0-9A-Z]{16}'), None),
    ("PRIVATE_KEY",     "critical", re.compile(r'-----BEGIN (RSA |EC )?PRIVATE KEY-----'), None),

    # PII — HIGH
    ("SSN",             "high",     re.compile(r'\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b'), None),
    ("CREDIT_CARD",     "high",     re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9][0-9])[0-9]{12})\b'), luhn_valid),
    ("PASSPORT",        "high",     re.compile(r'\b[A-Z]{1,2}[0-9]{6,9}\b'), None),

    # MEDIUM
    ("EMAIL",           "medium",   re.compile(r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b'), None),
    ("PHONE",           "medium",   re.compile(r'\b(?:\+?1[-.\s]?)?(?:\([0-9]{3}\)|[0-9]{3})[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b'), None),
    ("IP_ADDRESS",      "medium",   re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'), None),

    # LOW / informational
    ("DATE_OF_BIRTH",   "low",      re.compile(r'\b(?:DOB|date of birth|born on)[:\s]+\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}\b', re.IGNORECASE), None),
]

_JAILBREAK = re.compile(
    r'(?:'
    r'ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?|'
    r'you\s+are\s+now\s+(?:a\s+)?(?:dan|jailbreak|evil\s+ai)|'
    r'pretend\s+you\s+have\s+no\s+(?:restrictions?|guidelines?)|'
    r'bypass\s+(?:your\s+)?(?:safety|content)\s+(?:filter|restriction)|'
    r'act\s+as\s+if\s+you\s+have\s+no\s+(?:restrictions?|guidelines?)|'
    r'disregard\s+(?:all\s+)?(?:previous|prior)\s+(?:instructions?|prompt)|'
    r'i[\s.*_\-]*g[\s.*_\-]*n[\s.*_\-]*o[\s.*_\-]*r[\s.*_\-]*e'
    r')',
    re.IGNORECASE,
)

# ── Risk scoring ──────────────────────────────────────────────────────────────

_WEIGHTS = {
    "GITHUB_TOKEN": 9.8, "ANTHROPIC_KEY": 9.8, "OPENAI_KEY": 9.8,
    "STRIPE_SECRET": 9.7, "AWS_KEY": 9.6, "PRIVATE_KEY": 9.9,
    "SENDGRID_KEY": 9.5, "HUGGINGFACE_KEY": 9.2, "GITLAB_TOKEN": 9.5, "TWILIO_SID": 9.2,
    "SSN": 9.4, "CREDIT_CARD": 9.2, "PASSPORT": 8.8,
    "EMAIL": 4.0, "PHONE": 5.0, "IP_ADDRESS": 3.0,
    "DATE_OF_BIRTH": 5.5,
    "JAILBREAK": 10.0,
    "HIGH_ENTROPY_SECRET": 7.5,
    "JWT_TOKEN": 8.0,
    "LLM_SENSITIVE": 6.0,
}

def _compute_risk(pii_types: list[str], findings: list[dict]) -> tuple[float, str]:
    if not pii_types:
        return 0.0, "none"
    score = 0.0
    for t in pii_types:
        w = _WEIGHTS.get(t, 5.0)
        count = sum(1 for f in findings if f.get("type") == t)
        score += w * (1 + math.log1p(max(count - 1, 0))) * 10
    score = min(score, 100.0)

    if score >= 80:   severity = "critical"
    elif score >= 60: severity = "high"
    elif score >= 35: severity = "medium"
    elif score > 0:   severity = "low"
    else:             severity = "none"

    return round(score, 1), severity


# ── Classifier ────────────────────────────────────────────────────────────────

class Classifier:
    def scan(self, text: str) -> ScanResult:
        findings: list[dict] = []
        redacted = text

        # ── Regex + context negation ─────────────────────────────────────────
        for name, severity, pattern, validator in _PATTERNS:
            for m in pattern.finditer(text):
                start, end = m.start(), m.end()
                # Context negation window
                window = text[max(0, start - _NEGATION_WINDOW): min(len(text), end + _NEGATION_WINDOW)]
                if _NEGATION_WORDS.search(window):
                    continue
                raw = m.group()
                # Extra validation
                if validator and not validator(raw.replace(" ", "").replace("-", "")):
                    continue
                findings.append({
                    "type":     name,
                    "severity": severity,
                    "context":  f"...{text[max(0,start-20):end+20]}...",
                    "redacted": True,
                })
                placeholder = f"[{name}]"
                redacted = redacted.replace(raw, placeholder, 1)

        # ── Jailbreak ─────────────────────────────────────────────────────────
        if _JAILBREAK.search(text):
            findings.append({"type": "JAILBREAK", "severity": "critical", "context": "prompt injection pattern detected", "redacted": False})

        pii_types = list({f["type"] for f in findings})
        risk, severity = _compute_risk(pii_types, findings)

        # Flag for LLM assist when: medium risk, no hard pattern match, text is long enough to hide context
        needs_llm = (10 < risk < 60 and len(text) > 100) or \
                    any(kw in text.lower() for kw in ("my name is", "i was born", "my address", "my account"))

        return ScanResult(
            pii_types=pii_types,
            severity=severity,
            risk_score=risk,
            redacted_text=redacted,
            raw_findings=findings,
            needs_llm_assist=needs_llm,
            _original_text=text,
        )

    def structural_scan(self, text: str) -> list[dict]:
        """Detect JWTs, high-entropy tokens, base64 blobs."""
        findings = []

        # JWT detection
        jwt_pat = re.compile(r'eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+')
        for m in jwt_pat.finditer(text):
            findings.append({"type": "JWT_TOKEN", "severity": "high", "context": f"JWT found ({len(m.group())} chars)", "redacted": True})

        # High-entropy strings (>= 20 chars, entropy > 4.5 bits/char)
        token_pat = re.compile(r'\b[A-Za-z0-9+/\-_=]{20,}\b')
        uuid_pat  = re.compile(r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b', re.IGNORECASE)
        seen_hashes: set[str] = set()
        for m in token_pat.finditer(text):
            raw = m.group()
            if uuid_pat.match(raw):
                continue   # UUIDs are not secrets
            h = hashlib.md5(raw.encode()).hexdigest()
            if h in seen_hashes:
                continue
            seen_hashes.add(h)
            ent = shannon_entropy(raw)
            if ent >= 4.5:
                findings.append({
                    "type":     "HIGH_ENTROPY_SECRET",
                    "severity": "high",
                    "context":  f"entropy={ent:.2f} len={len(raw)}",
                    "redacted": True,
                })

        return findings

    async def llm_classify(self, text: str, existing_findings: list[dict]) -> list[dict]:
        """
        Ask the configured LLM whether the text contains sensitive information
        that regex didn't catch. Only called when needs_llm_assist=True.
        """
        api_key = os.environ.get("OPENAI_API_KEY") or os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            return []

        import urllib.request
        import json as _json

        prompt = (
            "You are a data security classifier. Analyze the following text and list any "
            "sensitive information types found that aren't obviously covered by regex (e.g. "
            "real names with DOB context, medical conditions, bank account descriptions, "
            "personal addresses). Reply ONLY with a JSON array like: "
            '[{"type": "MEDICAL_INFO", "severity": "high", "context": "..."}, ...] '
            "or [] if nothing sensitive. Be conservative — only flag clear cases.\n\n"
            f"Text:\n{text[:500]}"
        )

        try:
            body = _json.dumps({
                "model": "gpt-3.5-turbo",
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 200,
                "temperature": 0,
            }).encode()

            req = urllib.request.Request(
                "https://api.openai.com/v1/chat/completions",
                data=body,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {os.environ.get('OPENAI_API_KEY', '')}",
                },
            )
            with urllib.request.urlopen(req, timeout=8) as r:
                data = _json.loads(r.read())
            raw_content = data["choices"][0]["message"]["content"].strip()
            results = _json.loads(raw_content)
            if not isinstance(results, list):
                return []
            for item in results:
                item["redacted"] = True
            return results
        except Exception:
            return []
