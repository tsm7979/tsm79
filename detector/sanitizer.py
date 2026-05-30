"""
Centralized PII sanitizer for TSM.

Replaces scattered inline re.sub() calls in classifier.py with a single,
configurable, auditable sanitizer. Supports two strategies per rule:
  - redact:  replace match with [TYPE_REDACTED]
  - hash:    replace match with sha256(match)[:8] — preserves referential
             integrity (two occurrences of the same value get the same hash)
             while making the value unreadable.

Adapted from SecOps-ai DataSanitizer pattern.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable


class SensitivityLevel(str, Enum):
    PUBLIC       = "public"
    INTERNAL     = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED   = "restricted"


class RedactionStrategy(str, Enum):
    REDACT = "redact"   # replace with [TYPE_REDACTED]
    HASH   = "hash"     # replace with sha256[:8]


@dataclass
class SanitizationRule:
    name:        str
    pattern:     re.Pattern
    sensitivity: SensitivityLevel
    strategy:    RedactionStrategy = RedactionStrategy.REDACT
    validator:   Callable[[str], bool] | None = None  # optional Luhn etc.

    def replace(self, match: re.Match) -> str:
        value = match.group(0)
        if self.validator and not self.validator(value.replace(" ", "").replace("-", "")):
            return value  # validator rejected — not a real match
        if self.strategy == RedactionStrategy.HASH:
            digest = hashlib.sha256(value.encode()).hexdigest()[:8]
            return f"[{self.name}:{digest}]"
        return f"[{self.name}_REDACTED]"


@dataclass
class SanitizationResult:
    original_text:  str
    sanitized_text: str
    redactions:     list[dict]          = field(default_factory=list)
    requires_block: bool                = False  # True if RESTRICTED data found


def _luhn(digits: str) -> bool:
    """Luhn checksum for credit card validation."""
    d = [int(c) for c in digits if c.isdigit()]
    if len(d) < 13: return False
    total = 0
    for i, v in enumerate(reversed(d)):
        total += (v * 2 - 9 if v * 2 > 9 else v * 2) if i % 2 else v
    return total % 10 == 0


# ── Built-in rules (ordered: most specific first) ─────────────────────────────

_BUILTIN_RULES: list[SanitizationRule] = [
    SanitizationRule(
        name="OPENAI_KEY", sensitivity=SensitivityLevel.RESTRICTED, strategy=RedactionStrategy.REDACT,
        pattern=re.compile(r'sk-[a-zA-Z0-9]{48}'),
    ),
    SanitizationRule(
        name="ANTHROPIC_KEY", sensitivity=SensitivityLevel.RESTRICTED, strategy=RedactionStrategy.REDACT,
        pattern=re.compile(r'sk-ant-[a-zA-Z0-9\-_]{40,}'),
    ),
    SanitizationRule(
        name="GITHUB_TOKEN", sensitivity=SensitivityLevel.RESTRICTED, strategy=RedactionStrategy.REDACT,
        pattern=re.compile(r'(ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}'),
    ),
    SanitizationRule(
        name="AWS_KEY", sensitivity=SensitivityLevel.RESTRICTED, strategy=RedactionStrategy.REDACT,
        # Body class permits `_` and is `{16,}` — kept consistent with classifier.py
        # so demo / test fixtures of the form AKIA_DEMO_FIXTURE_AB are sanitized
        # without colliding with GitHub Push Protection's strict [A-Z0-9]{16} body.
        pattern=re.compile(r'AKIA[0-9A-Z_]{16,}'),
    ),
    SanitizationRule(
        name="PRIVATE_KEY", sensitivity=SensitivityLevel.RESTRICTED, strategy=RedactionStrategy.REDACT,
        pattern=re.compile(r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END \1PRIVATE KEY-----', re.DOTALL),
    ),
    SanitizationRule(
        name="JWT", sensitivity=SensitivityLevel.CONFIDENTIAL, strategy=RedactionStrategy.HASH,
        pattern=re.compile(r'eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+'),
    ),
    SanitizationRule(
        name="SSN", sensitivity=SensitivityLevel.RESTRICTED, strategy=RedactionStrategy.REDACT,
        pattern=re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
    ),
    SanitizationRule(
        name="CREDIT_CARD", sensitivity=SensitivityLevel.RESTRICTED, strategy=RedactionStrategy.REDACT,
        pattern=re.compile(
            r'\b(?:'
            r'4\d{3}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}'
            r'|5[1-5]\d{2}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}'
            r'|3[47]\d{2}[\s\-]?\d{6}[\s\-]?\d{5}'
            r'|6(?:011|5\d{2})[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}'
            r')\b'
        ),
        validator=_luhn,
    ),
    SanitizationRule(
        name="EMAIL", sensitivity=SensitivityLevel.CONFIDENTIAL, strategy=RedactionStrategy.HASH,
        pattern=re.compile(r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b'),
    ),
    SanitizationRule(
        name="PHONE", sensitivity=SensitivityLevel.CONFIDENTIAL, strategy=RedactionStrategy.REDACT,
        pattern=re.compile(r'(?<!\d)(\+?1[\s.\-]?)?\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}(?!\d)'),
    ),
]

_RESTRICTED_NAMES = {r.name for r in _BUILTIN_RULES if r.sensitivity == SensitivityLevel.RESTRICTED}


class Sanitizer:
    """
    Apply sanitization rules to text in order, tracking all redactions.

    Usage:
        s = Sanitizer()
        result = s.sanitize("My SSN is 123-45-6789 and key is sk-abc...48chars")
        print(result.sanitized_text)   # "My SSN is [SSN_REDACTED] and key is [OPENAI_KEY_REDACTED]"
        print(result.redactions)       # [{"rule": "SSN", ...}, {"rule": "OPENAI_KEY", ...}]
        print(result.requires_block)   # True (OPENAI_KEY is RESTRICTED)
    """

    def __init__(self, extra_rules: list[SanitizationRule] | None = None) -> None:
        self._rules = _BUILTIN_RULES + (extra_rules or [])

    def sanitize(self, text: str) -> SanitizationResult:
        redactions: list[dict] = []
        result_text = text

        for rule in self._rules:
            def _make_replacer(r: SanitizationRule) -> Callable[[re.Match], str]:
                def _replacer(m: re.Match) -> str:
                    replaced = r.replace(m)
                    if replaced != m.group(0):
                        redactions.append({
                            "rule":        r.name,
                            "sensitivity": r.sensitivity.value,
                            "strategy":    r.strategy.value,
                            "original_len": len(m.group(0)),
                        })
                    return replaced
                return _replacer
            result_text = rule.pattern.sub(_make_replacer(rule), result_text)

        requires_block = any(r["rule"] in _RESTRICTED_NAMES for r in redactions)
        return SanitizationResult(
            original_text=text,
            sanitized_text=result_text,
            redactions=redactions,
            requires_block=requires_block,
        )

    def sanitize_messages(self, messages: list[dict]) -> tuple[list[dict], list[dict]]:
        """Sanitize the content field of all user messages. Returns (sanitized_messages, all_redactions)."""
        all_redactions: list[dict] = []
        sanitized = []
        for msg in messages:
            if msg.get("role") == "user" and isinstance(msg.get("content"), str):
                result = self.sanitize(msg["content"])
                all_redactions.extend(result.redactions)
                sanitized.append({**msg, "content": result.sanitized_text})
            else:
                sanitized.append(msg)
        return sanitized, all_redactions


# Module-level singleton for convenience
_default_sanitizer = Sanitizer()


def sanitize(text: str) -> SanitizationResult:
    return _default_sanitizer.sanitize(text)
