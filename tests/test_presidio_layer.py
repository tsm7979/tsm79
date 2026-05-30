"""
Unit tests for detector.presidio_layer — Presidio NER wrapper.

Two test scenarios:
  A) Presidio NOT installed — all functions degrade gracefully (no imports, no crashes)
  B) Presidio IS installed — scan() produces correct TSM findings (mocked engine)

The heavy Presidio import is mocked so these tests run without the package installed.
"""

from __future__ import annotations

import importlib
import sys
import unittest
from unittest.mock import MagicMock, patch


# ── Helpers ───────────────────────────────────────────────────────────────────

def _reload_presidio_layer(presidio_installed: bool):
    """
    Reload detector.presidio_layer with presidio_analyzer available or not.
    Returns the freshly imported module.
    """
    # Remove cached module so importlib.util.find_spec gets re-evaluated
    sys.modules.pop("detector.presidio_layer", None)

    if presidio_installed:
        # Inject a mock presidio_analyzer package into sys.modules
        mock_pkg = MagicMock()
        mock_engine = MagicMock()
        mock_pkg.AnalyzerEngine = MagicMock(return_value=mock_engine)
        sys.modules.setdefault("presidio_analyzer", mock_pkg)
        sys.modules.setdefault("presidio_anonymizer", MagicMock())
    else:
        # Ensure the package is NOT findable
        sys.modules.pop("presidio_analyzer", None)
        sys.modules.pop("presidio_anonymizer", None)

    # Patch find_spec to control availability
    with patch("importlib.util.find_spec") as mock_find:
        mock_find.side_effect = lambda name: (
            MagicMock() if (presidio_installed and name == "presidio_analyzer") else None
        )
        import detector.presidio_layer as m
        return m


# ── Tests: Presidio not installed ────────────────────────────────────────────

class TestPresidioUnavailable(unittest.TestCase):
    """When presidio-analyzer is absent, all calls degrade silently."""

    def setUp(self):
        sys.modules.pop("detector.presidio_layer", None)
        sys.modules.pop("presidio_analyzer", None)
        sys.modules.pop("presidio_anonymizer", None)

    def _get_module(self):
        with patch("importlib.util.find_spec", return_value=None):
            import detector.presidio_layer as m
            return m

    def test_is_available_returns_false(self):
        m = self._get_module()
        self.assertFalse(m.is_available())

    def test_scan_returns_empty_list(self):
        m = self._get_module()
        results = m.scan("My name is John Smith and my SSN is 123-45-6789")
        self.assertEqual(results, [])

    def test_scan_short_text_returns_empty(self):
        m = self._get_module()
        self.assertEqual(m.scan("short"), [])

    def test_scan_and_anonymize_returns_original(self):
        m = self._get_module()
        text = "Some text with no changes"
        anon, findings = m.scan_and_anonymize(text)
        self.assertEqual(anon, text)
        self.assertEqual(findings, [])


# ── Tests: Presidio installed (mocked engine) ─────────────────────────────────

class _MockResult:
    """Fake Presidio RecognizerResult."""
    def __init__(self, entity_type: str, start: int, end: int, score: float = 0.85):
        self.entity_type = entity_type
        self.start = start
        self.end = end
        self.score = score


class TestPresidioAvailable(unittest.TestCase):
    """With a mocked AnalyzerEngine, verify TSM finding format and logic."""

    def setUp(self):
        # Clean slate
        for mod in ("detector.presidio_layer", "presidio_analyzer", "presidio_anonymizer"):
            sys.modules.pop(mod, None)

        # Build mock analyzer engine
        self.mock_engine = MagicMock()
        mock_pkg = MagicMock()
        mock_pkg.AnalyzerEngine.return_value = self.mock_engine
        sys.modules["presidio_analyzer"] = mock_pkg
        sys.modules["presidio_anonymizer"] = MagicMock()

        # Reload with Presidio "available"
        with patch("importlib.util.find_spec") as mock_find:
            mock_find.return_value = MagicMock()
            import detector.presidio_layer as m
            # Force lazy init to run
            m._analyzer = self.mock_engine
            m._PRESIDIO_OK = True
            self.m = m

    def tearDown(self):
        for mod in ("detector.presidio_layer", "presidio_analyzer", "presidio_anonymizer"):
            sys.modules.pop(mod, None)

    def test_is_available_returns_true(self):
        self.assertTrue(self.m.is_available())

    def test_scan_produces_tsm_finding(self):
        """SSN result should map to TSM type 'SSN' with high severity."""
        self.mock_engine.analyze.return_value = [
            _MockResult("US_SSN", start=14, end=25, score=0.95),
        ]
        text = "My SSN is: 123-45-6789"
        findings = self.m.scan(text)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f["type"], "SSN")
        self.assertEqual(f["severity"], "high")
        self.assertEqual(f["start"], 14)
        self.assertEqual(f["end"], 25)
        self.assertAlmostEqual(f["score"], 0.95, places=2)
        self.assertIn("context", f)
        self.assertFalse(f["redacted"])

    def test_scan_passes_score_threshold_to_engine(self):
        """scan() must pass score_threshold=_MIN_SCORE (0.60) to the engine."""
        self.mock_engine.analyze.return_value = []
        self.m.scan("email: test@example.com is here for you")
        call_kwargs = self.mock_engine.analyze.call_args.kwargs
        self.assertAlmostEqual(call_kwargs["score_threshold"], 0.60, places=2)

    def test_scan_deduplicates_overlapping_spans(self):
        """Two results on the same span should produce only one finding."""
        self.mock_engine.analyze.return_value = [
            _MockResult("PERSON", start=3, end=13, score=0.88),
            _MockResult("PERSON", start=3, end=13, score=0.91),  # duplicate span
        ]
        findings = self.m.scan("Hi John Smith how are you")
        self.assertEqual(len(findings), 1)

    def test_scan_maps_person_to_person_name(self):
        self.mock_engine.analyze.return_value = [
            _MockResult("PERSON", start=3, end=13, score=0.80),
        ]
        findings = self.m.scan("Hi John Smith how are you")
        self.assertEqual(findings[0]["type"], "PERSON_NAME")
        self.assertEqual(findings[0]["severity"], "medium")

    def test_scan_maps_credit_card(self):
        self.mock_engine.analyze.return_value = [
            _MockResult("CREDIT_CARD", start=5, end=21, score=0.99),
        ]
        findings = self.m.scan("CC: 4111111111111111 done")
        self.assertEqual(findings[0]["type"], "CREDIT_CARD")
        self.assertEqual(findings[0]["severity"], "high")

    def test_scan_maps_unknown_entity_type(self):
        """Unknown entity types fall back to themselves with 'medium' severity."""
        self.mock_engine.analyze.return_value = [
            _MockResult("SOME_FUTURE_TYPE", start=0, end=5, score=0.75),
        ]
        findings = self.m.scan("hello world from the future")
        self.assertEqual(findings[0]["type"], "SOME_FUTURE_TYPE")
        self.assertEqual(findings[0]["severity"], "medium")

    def test_scan_empty_results(self):
        self.mock_engine.analyze.return_value = []
        findings = self.m.scan("Nothing sensitive here.")
        self.assertEqual(findings, [])

    def test_scan_short_text_skipped(self):
        """Texts shorter than 15 chars are not sent to the engine."""
        findings = self.m.scan("hi there")
        self.mock_engine.analyze.assert_not_called()
        self.assertEqual(findings, [])

    def test_scan_context_field_contains_snippet(self):
        """Context field must embed a snippet of surrounding text."""
        text = "Patient SSN: 123-45-6789 admitted."
        self.mock_engine.analyze.return_value = [
            _MockResult("US_SSN", start=13, end=24, score=0.95),
        ]
        findings = self.m.scan(text)
        ctx = findings[0]["context"]
        self.assertIn("presidio:US_SSN@13:24", ctx)

    def test_scan_multiple_entity_types(self):
        self.mock_engine.analyze.return_value = [
            _MockResult("PERSON",        start=0,  end=10, score=0.85),
            _MockResult("EMAIL_ADDRESS", start=15, end=32, score=0.92),
            _MockResult("US_SSN",        start=38, end=49, score=0.98),
        ]
        text = "John Smith, john@example.com, 123-45-6789"
        findings = self.m.scan(text)
        types = [f["type"] for f in findings]
        self.assertIn("PERSON_NAME", types)
        self.assertIn("EMAIL", types)
        self.assertIn("SSN", types)

    def test_scan_engine_exception_returns_empty(self):
        """If the engine throws, scan() returns [] without propagating."""
        self.mock_engine.analyze.side_effect = RuntimeError("engine crashed")
        findings = self.m.scan("My SSN is 123-45-6789 and I need help")
        self.assertEqual(findings, [])

    def test_scan_and_anonymize_returns_findings(self):
        """scan_and_anonymize delegates to scan for findings list."""
        self.mock_engine.analyze.return_value = [
            _MockResult("US_SSN", start=10, end=21, score=0.95),
        ]
        mock_anon_engine = MagicMock()
        mock_anon_result = MagicMock()
        mock_anon_result.text = "My SSN is <REDACTED> please help."
        mock_anon_engine.anonymize.return_value = mock_anon_result

        with patch.dict(sys.modules, {"presidio_anonymizer": MagicMock(
            AnonymizerEngine=MagicMock(return_value=mock_anon_engine)
        )}):
            anon_text, findings = self.m.scan_and_anonymize("My SSN is 123-45-6789 please help.")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["type"], "SSN")

    def test_scan_and_anonymize_fallback_on_error(self):
        """If anonymizer throws, returns (original_text, scan_findings)."""
        self.mock_engine.analyze.return_value = [
            _MockResult("US_SSN", start=10, end=21, score=0.95),
        ]
        with patch.dict(sys.modules, {"presidio_anonymizer": MagicMock(
            AnonymizerEngine=MagicMock(side_effect=ImportError("missing"))
        )}):
            text = "My SSN is 123-45-6789 please help."
            anon_text, findings = self.m.scan_and_anonymize(text)
        # Fallback: original text + scan findings still returned
        self.assertIsInstance(anon_text, str)
        self.assertIsInstance(findings, list)


if __name__ == "__main__":
    unittest.main()
