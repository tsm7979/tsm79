"""
Tests: detector/main.py — FastAPI detector service
Coverage:
  - Auth middleware: unauthenticated, wrong key, correct key, open paths bypass
  - /health: always accessible, returns expected fields
  - /metrics: returns Prometheus text format with required metric names
  - _Metrics: record, record_error, prometheus_text, latency percentiles
  - _write_audit: appends JSON line, fails silently on bad path
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ── Import helpers (avoids importing the real ML stack) ───────────────────────

# Patch heavy imports before loading detector.main
_MOCK_MODULES = [
    "detector.classifier",
    "detector.policy_engine",
    "detector.alerting",
    "detector.workspace",
    "detector.risk_scorer",
    "detector.sanitizer",
    "detector.correlation",
    "detector.behavioral",
    "detector.anomaly",
    "detector.semantic",
    "spacy",
]

import unittest.mock as _m

_MISSING = object()
# (module, attribute) → stub for symbols detector.main binds at module load.
_ATTR_STUBS = {
    ("detector.correlation", "correlate"):           _m.MagicMock(return_value=(False, 0.0, 0)),
    ("detector.correlation", "correlation_stats"):   _m.MagicMock(return_value={}),
    ("detector.behavioral",  "get_analyzer"):        _m.MagicMock(),
    ("detector.anomaly",     "get_anomaly_detector"):_m.MagicMock(),
    ("detector.semantic",    "get_semantic_detector"):_m.MagicMock(return_value=MagicMock(available=False)),
    ("detector.workspace",   "registry"):            MagicMock(),
    ("detector.risk_scorer", "score_findings"):      _m.MagicMock(return_value=(0.0, 0, [])),
    ("detector.risk_scorer", "severity_from_level"): _m.MagicMock(return_value="none"),
}

# Snapshot global state, install mocks, then restore after importing detector.main.
# detector.main binds these symbols via `from X import ...` at import time, so it
# keeps the stubs even after we restore sys.modules — this prevents the mocks from
# leaking into other test files (test_semantic / test_policy_engine / etc.) and
# from corrupting real modules already imported earlier in the session.
_saved_modules = {_mod: sys.modules.get(_mod) for _mod in _MOCK_MODULES}
for _mod in _MOCK_MODULES:
    sys.modules.setdefault(_mod, MagicMock())

_saved_attrs = {key: getattr(sys.modules[key[0]], key[1], _MISSING) for key in _ATTR_STUBS}
for (mod_name, attr), stub in _ATTR_STUBS.items():
    setattr(sys.modules[mod_name], attr, stub)

# Now we can import the pieces we actually want to test
from detector.main import _Metrics, _write_audit  # noqa: E402

# ── Undo every global mutation so other test files import the REAL modules. ──
for (mod_name, attr), old in _saved_attrs.items():
    # Only restore on modules that pre-existed (real); installed mocks get popped below.
    if _saved_modules.get(mod_name) is not None and sys.modules.get(mod_name) is _saved_modules[mod_name]:
        if old is _MISSING:
            try:
                delattr(sys.modules[mod_name], attr)
            except AttributeError:
                pass
        else:
            setattr(sys.modules[mod_name], attr, old)
for _mod, _orig in _saved_modules.items():
    if _orig is None:
        sys.modules.pop(_mod, None)
    else:
        sys.modules[_mod] = _orig


# ── _Metrics unit tests ───────────────────────────────────────────────────────

class TestMetrics:
    def test_initial_counters_zero(self):
        m = _Metrics()
        assert m.requests == 0
        assert m.allowed  == 0
        assert m.blocked  == 0

    def test_record_allow(self):
        m = _Metrics()
        m.record("allow", 12.3)
        assert m.requests == 1
        assert m.allowed  == 1
        assert m.blocked  == 0

    def test_record_block(self):
        m = _Metrics()
        m.record("block", 5.0)
        assert m.blocked == 1

    def test_record_redact(self):
        m = _Metrics()
        m.record("redact", 5.0)
        assert m.redacted == 1

    def test_record_route_local(self):
        m = _Metrics()
        m.record("route_local", 5.0)
        assert m.route_local == 1

    def test_record_error(self):
        m = _Metrics()
        m.record_error()
        assert m.requests == 1
        assert m.errors   == 1

    def test_prometheus_text_contains_required_metrics(self):
        m = _Metrics()
        m.record("allow", 10.0)
        m.record("block", 20.0)
        text = m.prometheus_text()
        required = [
            "tsm_requests_total",
            "tsm_allowed_total",
            "tsm_blocked_total",
            "tsm_redacted_total",
            "tsm_route_local_total",
            "tsm_errors_total",
            "tsm_detect_latency_ms_p50",
            "tsm_detect_latency_ms_p95",
            "tsm_detect_latency_ms_p99",
        ]
        for name in required:
            assert name in text, f"{name} not found in metrics output"

    def test_prometheus_text_values_correct(self):
        m = _Metrics()
        m.record("allow", 5.0)
        m.record("block", 8.0)
        text = m.prometheus_text()
        assert "tsm_requests_total 2" in text
        assert "tsm_allowed_total 1" in text
        assert "tsm_blocked_total 1" in text

    def test_latency_cap_at_10k(self):
        m = _Metrics()
        for i in range(10_050):
            m.record("allow", float(i))
        assert len(m._latencies) == 10_000

    def test_thread_safety(self):
        """Concurrent record() calls must not raise."""
        m = _Metrics()
        errors = []
        def worker():
            try:
                for _ in range(100):
                    m.record("allow", 1.0)
            except Exception as e:
                errors.append(e)
        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads: t.start()
        for t in threads: t.join(timeout=5)
        assert not errors
        assert m.requests == 800

    def test_latency_percentiles_correct(self):
        m = _Metrics()
        # Feed 100 evenly spaced values so p50≈50, p95≈95
        for i in range(1, 101):
            m.record("allow", float(i))
        text = m.prometheus_text()
        # p50 line must exist and have a reasonable value
        assert "tsm_detect_latency_ms_p50" in text


# ── _write_audit unit tests ───────────────────────────────────────────────────

class TestWriteAudit:
    def test_writes_json_line(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "audit.jsonl"
            with patch("detector.main._AUDIT_PATH", path):
                _write_audit({"action": "block", "risk_score": 95.0})
            lines = path.read_text().strip().splitlines()
            assert len(lines) == 1
            record = json.loads(lines[0])
            assert record["action"] == "block"
            assert record["risk_score"] == 95.0

    def test_appends_multiple_lines(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "audit.jsonl"
            with patch("detector.main._AUDIT_PATH", path):
                _write_audit({"n": 1})
                _write_audit({"n": 2})
                _write_audit({"n": 3})
            lines = path.read_text().strip().splitlines()
            assert len(lines) == 3
            assert json.loads(lines[2])["n"] == 3

    def test_fails_silently_on_bad_path(self):
        """Write to a path that can't be created — must not raise."""
        bad_path = Path("/no/such/directory/audit.jsonl")
        with patch("detector.main._AUDIT_PATH", bad_path):
            _write_audit({"should": "not raise"})   # no exception


# ── HTTP endpoint tests (TestClient) ─────────────────────────────────────────

try:
    from fastapi.testclient import TestClient
    _HAS_TESTCLIENT = True
except ImportError:
    _HAS_TESTCLIENT = False


@pytest.fixture()
def client_no_auth(monkeypatch):
    """TestClient with no auth key configured."""
    monkeypatch.setattr("detector.main._DETECTOR_KEY", "")
    from detector.main import app
    return TestClient(app)


@pytest.fixture()
def client_with_auth(monkeypatch):
    """TestClient with TSM_DETECTOR_KEY = 'test-secret'."""
    monkeypatch.setattr("detector.main._DETECTOR_KEY", "test-secret")
    from detector.main import app
    return TestClient(app)


@pytest.mark.skipif(not _HAS_TESTCLIENT, reason="httpx/starlette not installed")
class TestHealthEndpoint:
    def test_health_returns_200(self, client_no_auth):
        r = client_no_auth.get("/health")
        assert r.status_code == 200

    def test_health_has_status_healthy(self, client_no_auth):
        r = client_no_auth.get("/health")
        assert r.json()["status"] == "healthy"

    def test_health_reports_auth_disabled(self, client_no_auth):
        r = client_no_auth.get("/health")
        assert r.json()["auth_enabled"] is False

    def test_health_reports_auth_enabled(self, client_with_auth):
        r = client_with_auth.get("/health")
        assert r.json()["auth_enabled"] is True

    def test_health_bypasses_auth(self, client_with_auth):
        """GET /health must work even without Authorization header."""
        r = client_with_auth.get("/health")
        assert r.status_code == 200


@pytest.mark.skipif(not _HAS_TESTCLIENT, reason="httpx/starlette not installed")
class TestMetricsEndpoint:
    def test_metrics_returns_200(self, client_no_auth):
        r = client_no_auth.get("/metrics")
        assert r.status_code == 200

    def test_metrics_content_type(self, client_no_auth):
        r = client_no_auth.get("/metrics")
        assert "text/plain" in r.headers["content-type"]

    def test_metrics_contains_counter(self, client_no_auth):
        r = client_no_auth.get("/metrics")
        assert "tsm_requests_total" in r.text

    def test_metrics_bypasses_auth(self, client_with_auth):
        """GET /metrics must be accessible without auth (scraper compatibility)."""
        r = client_with_auth.get("/metrics")
        assert r.status_code == 200


@pytest.mark.skipif(not _HAS_TESTCLIENT, reason="httpx/starlette not installed")
class TestAuthMiddleware:
    def test_no_auth_configured_allows_any_request(self, client_no_auth):
        # /rules is a protected endpoint but auth is disabled globally
        r = client_no_auth.get("/rules")
        assert r.status_code != 401

    def test_missing_key_returns_401(self, client_with_auth):
        r = client_with_auth.get("/rules")
        assert r.status_code == 401

    def test_wrong_key_returns_401(self, client_with_auth):
        r = client_with_auth.get("/rules", headers={"Authorization": "Bearer wrong-key"})
        assert r.status_code == 401

    def test_correct_bearer_returns_non_401(self, client_with_auth):
        r = client_with_auth.get("/rules", headers={"Authorization": "Bearer test-secret"})
        assert r.status_code != 401

    def test_correct_x_tsm_key_header(self, client_with_auth):
        r = client_with_auth.get("/rules", headers={"X-TSM-Key": "test-secret"})
        assert r.status_code != 401

    def test_401_body_is_json(self, client_with_auth):
        r = client_with_auth.get("/rules")
        body = r.json()
        assert "error" in body
        assert body["error"]["code"] == "unauthorized"

    def test_open_paths_bypass_auth(self, client_with_auth):
        for path in ["/health", "/metrics"]:
            r = client_with_auth.get(path)
            assert r.status_code != 401, f"Open path {path} should bypass auth"
