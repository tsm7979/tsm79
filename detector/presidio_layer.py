"""
Microsoft Presidio NER layer — semantic PII detection.

Why Presidio on top of regex:
  Regex catches "123-45-6789". It cannot catch:
    "John Smith, born March 4 1985, resides at 14 Elm Street"  → PERSON + DOB + LOCATION
    "My account ending 7821 with routing 021000021"             → BANK_ACCOUNT (context)
    "Patient: Jane Doe, Dx: Type 2 Diabetes, Rx: Metformin"    → MEDICAL_INFO

  Presidio combines:
    1. ML-based Named Entity Recognition (spaCy transformers pipeline)
    2. Deterministic recognizers (Luhn CC, ABA routing, IBAN checksum)
    3. Context-aware post-processing (words near entity boost/suppress score)
    4. International PII (EU IBANs, UK NHS numbers, AU TFNs, etc.)

  TSM treats Presidio as an *optional enrichment layer*: if presidio-analyzer
  is not installed, this module returns [] and detection falls back to the
  regex + spaCy layers. Install with:
    pip install presidio-analyzer presidio-anonymizer
    python -m spacy download en_core_web_lg   # or en_core_web_trf for best accuracy

Mapping policy:
  Presidio entity type  → TSM finding type  (severity)
  PERSON                → PERSON_NAME       (medium)
  PHONE_NUMBER          → PHONE             (medium)
  EMAIL_ADDRESS         → EMAIL             (medium)
  LOCATION              → LOCATION          (low)
  CREDIT_CARD           → CREDIT_CARD       (high)     + Luhn validated
  US_SSN                → SSN               (high)
  IBAN_CODE             → BANK_ACCOUNT      (high)
  IP_ADDRESS            → IP_ADDRESS        (medium)
  US_BANK_NUMBER        → BANK_ACCOUNT      (high)
  MEDICAL_LICENSE       → MEDICAL_INFO      (high)
  DATE_TIME             → DATE_INFO         (low)
  NRP (nat./rel./pol.)  → SENSITIVE_CATEGORY (high) — GDPR Art 9 special category
  URL                   → URL               (low)
"""
from __future__ import annotations

import threading
from typing import Any

# ── Entity → TSM type map ─────────────────────────────────────────────────────

_ENTITY_MAP: dict[str, tuple[str, str]] = {
    "PERSON":           ("PERSON_NAME",       "medium"),
    "PHONE_NUMBER":     ("PHONE",             "medium"),
    "EMAIL_ADDRESS":    ("EMAIL",             "medium"),
    "LOCATION":         ("LOCATION",          "low"),
    "CREDIT_CARD":      ("CREDIT_CARD",       "high"),
    "US_SSN":           ("SSN",               "high"),
    "IBAN_CODE":        ("BANK_ACCOUNT",      "high"),
    "US_BANK_NUMBER":   ("BANK_ACCOUNT",      "high"),
    "IP_ADDRESS":       ("IP_ADDRESS",        "medium"),
    "MEDICAL_LICENSE":  ("MEDICAL_INFO",      "high"),
    "DATE_TIME":        ("DATE_INFO",         "low"),
    "NRP":              ("SENSITIVE_CATEGORY","high"),
    "URL":              ("URL",               "low"),
    "US_PASSPORT":      ("PASSPORT",          "high"),
    "UK_NHS":           ("NATIONAL_ID",       "high"),
    "AU_TFN":           ("NATIONAL_ID",       "high"),
    "IN_PAN":           ("NATIONAL_ID",       "high"),
}

# Minimum Presidio confidence score to accept as a TSM finding.
# 0.6 = balanced; raise to 0.8 for fewer false positives at the cost of misses.
_MIN_SCORE = 0.60

# Entities to explicitly request from Presidio (empty list = all supported).
_REQUESTED_ENTITIES = list(_ENTITY_MAP.keys())

# ── Presidio availability ─────────────────────────────────────────────────────

_analyzer     = None
_init_lock    = threading.Lock()
_PRESIDIO_OK  = False


def _init_presidio() -> None:
    """Lazy-initialise Presidio on first use (heavy import, ~500ms)."""
    global _analyzer, _PRESIDIO_OK
    if _analyzer is not None or not _PRESIDIO_OK:
        return
    with _init_lock:
        if _analyzer is not None:
            return
        try:
            from presidio_analyzer import AnalyzerEngine  # type: ignore
            _analyzer = AnalyzerEngine()
            _PRESIDIO_OK = True
        except Exception:
            _analyzer    = None
            _PRESIDIO_OK = False


try:
    # Probe for the package without loading the full engine (avoids 500ms cold start)
    import importlib.util as _ilu
    _PRESIDIO_OK = _ilu.find_spec("presidio_analyzer") is not None
except Exception:
    _PRESIDIO_OK = False


# ── Public API ────────────────────────────────────────────────────────────────

@property
def available() -> bool:
    """True when presidio-analyzer is installed."""
    return _PRESIDIO_OK


def scan(text: str, language: str = "en") -> list[dict]:
    """
    Run Presidio analysis on `text` and return TSM-format findings.

    Each finding:
        {"type": str, "severity": str, "context": str,
         "redacted": bool, "score": float, "start": int, "end": int}

    Empty list when Presidio is unavailable or text is too short.
    """
    if not _PRESIDIO_OK or len(text) < 15:
        return []

    _init_presidio()
    if _analyzer is None:
        return []

    try:
        results = _analyzer.analyze(
            text=text,
            entities=_REQUESTED_ENTITIES,
            language=language,
            score_threshold=_MIN_SCORE,
        )
    except Exception:
        return []

    findings: list[dict] = []
    seen_spans: set[tuple[int, int]] = set()

    for r in results:
        # Skip duplicate spans (multiple recognizers may fire on the same span)
        span = (r.start, r.end)
        if span in seen_spans:
            continue
        seen_spans.add(span)

        tsm_type, severity = _ENTITY_MAP.get(r.entity_type, (r.entity_type, "medium"))
        snippet = text[max(0, r.start - 15): r.end + 15]

        findings.append({
            "type":     tsm_type,
            "severity": severity,
            "context":  f"presidio:{r.entity_type}@{r.start}:{r.end} score={r.score:.2f} …{snippet}…",
            "redacted": False,   # advisory; sanitizer decides replacement strategy
            "score":    round(r.score, 3),
            "start":    r.start,
            "end":      r.end,
        })

    return findings


def scan_and_anonymize(text: str, language: str = "en") -> tuple[str, list[dict]]:
    """
    Run Presidio analysis AND anonymization in one call.

    Returns (anonymized_text, findings).  Useful when you need the Presidio-
    redacted version of the text (with spans replaced) rather than TSM's own
    tokenizer.  TSM normally prefers its own tokenizer so it can detokenize
    on the response path; this is provided for completeness.
    """
    if not _PRESIDIO_OK:
        return text, []

    _init_presidio()
    if _analyzer is None:
        return text, []

    try:
        from presidio_anonymizer import AnonymizerEngine  # type: ignore
        anonymizer = AnonymizerEngine()
        results    = _analyzer.analyze(text=text, language=language, score_threshold=_MIN_SCORE)
        anon       = anonymizer.anonymize(text=text, analyzer_results=results)
        findings   = scan(text, language=language)
        return anon.text, findings
    except Exception:
        return text, scan(text, language=language)


def is_available() -> bool:
    """Return True when Presidio is installed and the engine can be initialised."""
    return _PRESIDIO_OK
