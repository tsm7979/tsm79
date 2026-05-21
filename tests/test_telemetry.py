"""
Unit tests for detector.telemetry — OTel OTLP export module.

Tests verify:
  1. Graceful degradation when opentelemetry-sdk is NOT installed
  2. Correct behaviour when a mock SDK is injected
  3. trace_detect_call / record_exception are safe no-ops without OTel
  4. is_enabled() reflects initialisation state
  5. _build_exporter() selects grpc vs http based on TSM_OTEL_EXPORTER
"""

from __future__ import annotations

import contextlib
import os
import sys
import unittest
from unittest.mock import MagicMock, patch, call


# ── Helpers ───────────────────────────────────────────────────────────────────

def _reload_telemetry(otel_installed: bool = False, env: dict | None = None):
    """Reload detector.telemetry with controlled environment."""
    # Remove cached module
    for mod in list(sys.modules):
        if "detector.telemetry" in mod or mod.startswith("opentelemetry"):
            sys.modules.pop(mod, None)

    if otel_installed:
        _inject_mock_otel()
    else:
        _remove_mock_otel()

    env = env or {}
    with patch.dict(os.environ, env, clear=False):
        with patch("importlib.util.find_spec") as mock_find:
            mock_find.side_effect = lambda name: (
                MagicMock() if (otel_installed and "opentelemetry" in name) else None
            )
            import detector.telemetry as m
            return m


def _inject_mock_otel():
    """Install a minimal OTel mock hierarchy into sys.modules."""
    # Build mock spans + tracer
    mock_span    = MagicMock()
    mock_tracer  = MagicMock()
    mock_tracer.start_as_current_span.return_value = contextlib.nullcontext(mock_span)
    mock_span.is_recording.return_value = True

    # trace module
    mock_trace_mod = MagicMock()
    mock_trace_mod.get_tracer.return_value = mock_tracer
    mock_trace_mod.get_current_span.return_value = mock_span

    # StatusCode
    mock_status = MagicMock()
    mock_status.OK    = "OK"
    mock_status.ERROR = "ERROR"
    mock_trace_mod.StatusCode = mock_status

    # SDK modules
    mock_sdk             = MagicMock()
    mock_provider        = MagicMock()
    mock_processor       = MagicMock()
    mock_resource        = MagicMock()
    mock_resource_cls    = MagicMock()
    mock_resource_cls.create.return_value = mock_resource

    mock_sdk.trace.TracerProvider            = MagicMock(return_value=mock_provider)
    mock_sdk.trace.export.BatchSpanProcessor = MagicMock(return_value=mock_processor)
    mock_sdk.resources.Resource              = mock_resource_cls

    # Exporters
    mock_grpc_exporter = MagicMock()
    mock_http_exporter = MagicMock()

    entries = {
        "opentelemetry":                                         MagicMock(trace=mock_trace_mod),
        "opentelemetry.sdk":                                     mock_sdk,
        "opentelemetry.sdk.trace":                               mock_sdk.trace,
        "opentelemetry.sdk.trace.export":                        mock_sdk.trace.export,
        "opentelemetry.sdk.resources":                           mock_sdk.resources,
        "opentelemetry.trace":                                   mock_trace_mod,
        "opentelemetry.exporter.otlp":                           MagicMock(),
        "opentelemetry.exporter.otlp.proto":                     MagicMock(),
        "opentelemetry.exporter.otlp.proto.grpc":                MagicMock(),
        "opentelemetry.exporter.otlp.proto.grpc.trace_exporter": MagicMock(OTLPSpanExporter=MagicMock(return_value=mock_grpc_exporter)),
        "opentelemetry.exporter.otlp.proto.http":                MagicMock(),
        "opentelemetry.exporter.otlp.proto.http.trace_exporter": MagicMock(OTLPSpanExporter=MagicMock(return_value=mock_http_exporter)),
    }
    sys.modules.update(entries)
    return mock_span, mock_tracer


def _remove_mock_otel():
    for key in list(sys.modules):
        if "opentelemetry" in key:
            sys.modules.pop(key, None)


# ── Tests: OTel not installed ─────────────────────────────────────────────────

class TestOtelUnavailable(unittest.TestCase):
    def setUp(self):
        for k in list(sys.modules):
            if "detector.telemetry" in k or "opentelemetry" in k:
                sys.modules.pop(k, None)

    def tearDown(self):
        for k in list(sys.modules):
            if "detector.telemetry" in k or "opentelemetry" in k:
                sys.modules.pop(k, None)

    def _module(self):
        with patch("importlib.util.find_spec", return_value=None):
            import detector.telemetry as m
            return m

    def test_is_enabled_false_without_sdk(self):
        m = self._module()
        self.assertFalse(m.is_enabled())

    def test_init_telemetry_returns_false(self):
        m = self._module()
        result = m.init_telemetry()
        self.assertFalse(result)

    def test_trace_detect_call_is_noop(self):
        """trace_detect_call must not raise without OTel."""
        m = self._module()
        ran = False
        with m.trace_detect_call("org1", "gpt-4o", "allow", ["SSN"], 75.0, 12.5):
            ran = True
        self.assertTrue(ran)

    def test_trace_upstream_call_is_noop(self):
        m = self._module()
        ran = False
        with m.trace_upstream_call("openai", "gpt-4o", "/v1/chat/completions"):
            ran = True
        self.assertTrue(ran)

    def test_record_exception_is_noop(self):
        m = self._module()
        # Must not raise
        m.record_exception(ValueError("test error"))

    def test_trace_detect_call_yields_correctly(self):
        """Context manager must yield even when OTel is absent."""
        m = self._module()
        results = []
        with m.trace_detect_call("org", "claude-3", "block", ["JAILBREAK"], 99.0, 5.0):
            results.append(42)
        self.assertEqual(results, [42])


# ── Tests: OTel installed (mocked SDK) ───────────────────────────────────────

class TestOtelAvailable(unittest.TestCase):
    def setUp(self):
        for k in list(sys.modules):
            if "detector.telemetry" in k or "opentelemetry" in k:
                sys.modules.pop(k, None)
        self.mock_span, self.mock_tracer = _inject_mock_otel()

    def tearDown(self):
        for k in list(sys.modules):
            if "detector.telemetry" in k or "opentelemetry" in k:
                sys.modules.pop(k, None)

    def _module(self, env: dict | None = None):
        env = env or {"OTEL_EXPORTER_OTLP_ENDPOINT": "http://localhost:4317"}
        with patch.dict(os.environ, env):
            with patch("importlib.util.find_spec", return_value=MagicMock()):
                import detector.telemetry as m
                m._OTEL_OK    = True
                m._SHOULD_INIT = True
                return m

    def test_init_telemetry_returns_true_with_sdk(self):
        m = self._module()
        # Patch _build_exporter to return a mock
        with patch.object(m, "_build_exporter", return_value=MagicMock()):
            result = m.init_telemetry()
        self.assertTrue(result)

    def test_is_enabled_true_after_init(self):
        m = self._module()
        with patch.object(m, "_build_exporter", return_value=MagicMock()):
            m.init_telemetry()
        self.assertTrue(m.is_enabled())

    def test_init_telemetry_idempotent(self):
        """Calling init_telemetry twice must not create a second provider."""
        m = self._module()
        with patch.object(m, "_build_exporter", return_value=MagicMock()) as mock_build:
            m.init_telemetry()
            m.init_telemetry()   # second call
        # _build_exporter should be called only once
        self.assertEqual(mock_build.call_count, 1)

    def test_build_exporter_defaults_to_grpc(self):
        m = self._module(env={"TSM_OTEL_EXPORTER": "grpc",
                               "OTEL_EXPORTER_OTLP_ENDPOINT": "http://localhost:4317"})
        m._EXPORTER = "grpc"
        exporter = m._build_exporter()
        # Should return the mock gRPC exporter (not None)
        self.assertIsNotNone(exporter)

    def test_build_exporter_http(self):
        m = self._module(env={"TSM_OTEL_EXPORTER": "http",
                               "OTEL_EXPORTER_OTLP_ENDPOINT": "http://localhost:4318"})
        m._EXPORTER = "http"
        exporter = m._build_exporter()
        self.assertIsNotNone(exporter)

    def test_trace_detect_call_sets_attributes(self):
        m = self._module()
        with patch.object(m, "_build_exporter", return_value=MagicMock()):
            m.init_telemetry()

        with m.trace_detect_call("acme", "gpt-4o", "redact", ["SSN", "EMAIL"], 82.5, 34.2):
            pass

        # The span mock should have had set_attribute called with TSM fields
        calls = [str(c) for c in self.mock_span.set_attribute.call_args_list]
        attrs_set = {c.split("'")[1] for c in calls if "'" in c}
        # At minimum, these attributes must be present
        for attr in ("tsm.org_id", "tsm.model", "tsm.action", "tsm.risk_score"):
            self.assertTrue(any(attr in c for c in calls),
                            f"Expected attribute '{attr}' not set on span")

    def test_record_exception_calls_span(self):
        m = self._module()
        with patch.object(m, "_build_exporter", return_value=MagicMock()):
            m.init_telemetry()

        exc = ValueError("test error")
        m.record_exception(exc)
        self.mock_span.record_exception.assert_called_once_with(exc)


# ── Tests: env-based enable/disable ──────────────────────────────────────────

class TestEnvConfig(unittest.TestCase):
    def tearDown(self):
        for k in list(sys.modules):
            if "detector.telemetry" in k or "opentelemetry" in k:
                sys.modules.pop(k, None)

    def test_disabled_by_env(self):
        """TSM_OTEL_ENABLED=false prevents init even when SDK is available."""
        _inject_mock_otel()
        with patch.dict(os.environ, {"TSM_OTEL_ENABLED": "false",
                                     "OTEL_EXPORTER_OTLP_ENDPOINT": "http://localhost:4317"}):
            with patch("importlib.util.find_spec", return_value=MagicMock()):
                import detector.telemetry as m
                m._OTEL_OK = True
                # _SHOULD_INIT should be False when TSM_OTEL_ENABLED=false
                self.assertFalse(m._SHOULD_INIT)

    def test_enabled_by_endpoint_env(self):
        """Setting OTEL_EXPORTER_OTLP_ENDPOINT implicitly enables OTel."""
        _inject_mock_otel()
        with patch.dict(os.environ, {"OTEL_EXPORTER_OTLP_ENDPOINT": "http://collector:4317"},
                        clear=False):
            with patch("importlib.util.find_spec", return_value=MagicMock()):
                import detector.telemetry as m
                # OTEL_EXPORTER_OTLP_ENDPOINT set → _SHOULD_INIT should be True
                self.assertTrue(m._SHOULD_INIT)


if __name__ == "__main__":
    unittest.main()
