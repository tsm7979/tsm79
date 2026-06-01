"""
Normalization layer — anti-evasion preprocessing (deterministic, no AI).

Adversaries defeat naive pattern matching with formatting tricks: unicode
homoglyphs, zero-width joiners, leetspeak, whitespace splitting, base64/hex
encoding, case games. This module aggressively canonicalizes input BEFORE any
signature/entropy/policy layer runs, so a single normalized form is what the
detectors actually see.

Design rules:
  - Pure functions, deterministic, side-effect free.
  - Every transform is independently testable.
  - We return BOTH the normalized text and a record of which transforms fired,
    so the decision layer can treat "heavy obfuscation" as its own risk signal.
  - We never *trust* normalization to remove a threat; we use it to make threats
    visible to the matchers and to flag evasion attempts.

Used by both the ingress (prompt) path and the egress (response) path.
"""
from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass, field

# ── Homoglyph map: common confusables → ASCII ───────────────────────────────
# Cyrillic/Greek/fullwidth lookalikes attackers use to dodge keyword filters.
_HOMOGLYPHS = {
    # Cyrillic
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "А": "A", "Е": "E", "О": "O", "Р": "P", "С": "C", "У": "Y", "Х": "X",
    "к": "k", "м": "m", "н": "h", "т": "t", "в": "b",
    "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ɡ": "g", "І": "I", "Ј": "J",
    # Greek
    "ο": "o", "α": "a", "ε": "e", "ρ": "p", "τ": "t", "ι": "i", "κ": "k",
    "Ο": "O", "Α": "A", "Ε": "E", "Ρ": "P", "Τ": "T", "ν": "v", "υ": "u",
    "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Β": "B", "Η": "H", "Ζ": "Z",
    # Fullwidth ASCII (FF01–FF5E map to 21–7E)
}

# Leetspeak → letter. Applied only for keyword-family matching, not for the
# value-bearing normalized text (so we don't corrupt real tokens).
_LEET = {
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t",
    "@": "a", "$": "s", "!": "i", "|": "l",
}

_ZERO_WIDTH = dict.fromkeys(
    [0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x00AD, 0x180E], None
)

_WS_RE = re.compile(r"[ \t  -   　]+")
_B64_RE = re.compile(r"\b[A-Za-z0-9+/]{16,}={0,2}\b")
_HEX_RE = re.compile(r"\b(?:0x)?[0-9a-fA-F]{16,}\b")


@dataclass
class Normalized:
    """Result of normalization."""
    text: str                       # canonical form for value matching
    folded: str                     # extra-aggressive form for keyword families
    transforms: list[str] = field(default_factory=list)
    decoded_segments: list[str] = field(default_factory=list)  # base64/hex payloads surfaced

    @property
    def obfuscation_score(self) -> float:
        """0–1 heuristic: how much evasion machinery was needed. High = suspicious."""
        weights = {
            "homoglyph": 0.35, "zero_width": 0.4, "leetspeak": 0.2,
            "base64_decode": 0.3, "hex_decode": 0.25, "whitespace_collapse": 0.05,
            "unicode_nfkc": 0.05, "case_fold": 0.0,
        }
        return min(1.0, sum(weights.get(t, 0.1) for t in self.transforms))


def _strip_zero_width(s: str) -> tuple[str, bool]:
    out = s.translate(_ZERO_WIDTH)
    return out, (out != s)


def _map_homoglyphs(s: str) -> tuple[str, bool]:
    fired = False
    chars = []
    for ch in s:
        repl = _HOMOGLYPHS.get(ch)
        if repl is not None:
            chars.append(repl)
            fired = True
        else:
            chars.append(ch)
    return "".join(chars), fired


def _collapse_ws(s: str) -> tuple[str, bool]:
    out = _WS_RE.sub(" ", s)
    return out, (out != s)


# A leet substitution disguising a word: a leet char with letters on BOTH sides
# in the same run (e.g. "1gn0re" -> "g_n", "byp4ss" -> "p4s"), not incidental
# tokens like "Q3" or "v2" where the digit is at a boundary.
_LEET_WORD_RE = re.compile(r"[a-zA-Z][0-9@$!|][a-zA-Z]")


def _leet_fold(s: str) -> str:
    return "".join(_LEET.get(ch, ch) for ch in s.lower())


def _try_decode_segments(s: str) -> list[str]:
    """Surface base64/hex payloads as decoded text so matchers see hidden secrets.
    We only keep decodes that look like printable text or known secret shapes."""
    found: list[str] = []
    for m in _B64_RE.finditer(s):
        seg = m.group(0)
        try:
            pad = seg + "=" * (-len(seg) % 4)
            dec = base64.b64decode(pad, validate=True)
            txt = dec.decode("utf-8", "strict")
            if txt.isprintable() and len(txt) >= 8:
                found.append(txt)
        except (binascii.Error, ValueError, UnicodeDecodeError):
            pass
    for m in _HEX_RE.finditer(s):
        seg = m.group(0).removeprefix("0x")
        if len(seg) % 2 == 0:
            try:
                dec = bytes.fromhex(seg)
                txt = dec.decode("utf-8", "strict")
                if txt.isprintable() and len(txt) >= 8:
                    found.append(txt)
            except (ValueError, UnicodeDecodeError):
                pass
    return found


def normalize(text: str, *, decode_payloads: bool = True) -> Normalized:
    """Aggressively canonicalize `text`. Returns a Normalized with the canonical
    form, an extra-folded form for keyword matching, the transforms that fired,
    and any decoded base64/hex payloads surfaced for re-scanning."""
    transforms: list[str] = []

    # 1. Unicode NFKC (fullwidth → ASCII, ligatures → letters, etc.)
    nfkc = unicodedata.normalize("NFKC", text)
    if nfkc != text:
        transforms.append("unicode_nfkc")
    s = nfkc

    # 2. Zero-width / soft-hyphen stripping
    s, zw = _strip_zero_width(s)
    if zw:
        transforms.append("zero_width")

    # 3. Homoglyph mapping
    s, hg = _map_homoglyphs(s)
    if hg:
        transforms.append("homoglyph")

    # 4. Whitespace canonicalization
    s, ws = _collapse_ws(s)
    if ws:
        transforms.append("whitespace_collapse")

    canonical = s.strip()

    # 5. Decode hidden payloads (surfaced separately; not spliced into canonical)
    decoded: list[str] = []
    if decode_payloads:
        decoded = _try_decode_segments(canonical)
        if decoded:
            transforms.append("base64_decode" if any(c.isalpha() for c in "".join(decoded)) else "hex_decode")

    # 6. Extra-aggressive fold for keyword families (case + leet).
    # The folded form is ALWAYS produced (for keyword matching). But leetspeak is
    # only counted as an *evasion signal* when a folded token becomes a real word
    # it wasn't before — i.e. a leet substitution sits inside an alphabetic run
    # of length >= 4 (disguising a word like "1gn0r3"), not incidental tokens
    # like "Q3" or "v2". This keeps the obfuscation score quiet on benign text.
    folded = _leet_fold(canonical)
    if folded != canonical.lower() and _LEET_WORD_RE.search(canonical):
        transforms.append("leetspeak")
    if canonical != canonical.lower():
        transforms.append("case_fold")

    return Normalized(
        text=canonical,
        folded=folded,
        transforms=transforms,
        decoded_segments=decoded,
    )


# Convenience: the combined search corpus a matcher should scan — canonical text
# plus any decoded payloads — so hidden secrets are never missed.
def search_corpus(n: Normalized) -> str:
    parts = [n.text]
    parts.extend(n.decoded_segments)
    return "\n".join(parts)
