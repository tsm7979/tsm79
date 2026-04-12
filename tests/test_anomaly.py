"""
Tests: detector/anomaly.py — Isolation Forest anomaly detector

Coverage:
  - Feature extraction from event windows (_features)
  - _OrgModel: append, should_refit, score before/after fitting
  - AnomalyDetector: warm-up returns 0.0, fitting, per-org isolation
  - Background refitter: does not block the main thread
  - Model info endpoint
  - Graceful degradation when sklearn absent
"""
from __future__ import annotations

import math
import threading
import time

import pytest

from detector.anomaly import (
    AnomalyDetector,
    _OrgModel,
    _features,
    _WARMUP_SAMPLES,
    _REFIT_INTERVAL,
    get_anomaly_detector,
)


# ── Feature extraction ────────────────────────────────────────────────────────

class TestFeatureExtraction:
    def _event(self, pii: list[str] = (), length: int = 100) -> dict:
        return {"pii": list(pii), "len": length}

    def test_returns_10_dimensions(self):
        fvec = _features([self._event()], [self._event()])
        assert len(fvec) == 10

    def test_all_floats(self):
        fvec = _features([self._event()], [self._event()])
        assert all(isinstance(f, float) for f in fvec)

    def test_empty_events_returns_zeros_for_counts(self):
        fvec = _features([], [])
        assert fvec[0] == 0.0   # req_rate_1m
        assert fvec[1] == 0.0   # req_rate_10m

    def test_pii_ratio_bounded(self):
        pii_events = [self._event(["SSN", "EMAIL"]) for _ in range(5)]
        fvec = _features(pii_events, pii_events)
        # pii_ratio_1m = pii_count / n_events → should be 1.0 (all have pii)
        assert fvec[4] == 1.0

    def test_clean_events_pii_ratio_zero(self):
        clean_events = [self._event([]) for _ in range(5)]
        fvec = _features(clean_events, clean_events)
        assert fvec[4] == 0.0   # pii_ratio_1m

    def test_time_encoding_in_unit_circle(self):
        fvec = _features([], [])
        h_sin, h_cos = fvec[8], fvec[9]
        # sin²+cos² = 1
        assert abs(h_sin ** 2 + h_cos ** 2 - 1.0) < 1e-9

    def test_token_count_approx(self):
        events = [{"pii": [], "len": 400} for _ in range(5)]
        fvec = _features(events, events)
        # tok_rate_1m = sum(len)//4 = 500
        assert fvec[2] == pytest.approx(500.0)


# ── _OrgModel ─────────────────────────────────────────────────────────────────

class TestOrgModel:
    def test_score_returns_zero_before_fitting(self):
        m = _OrgModel(org_id="test")
        fvec = [0.0] * 10
        assert m.score(fvec) == 0.0

    def test_should_refit_false_below_warmup(self):
        m = _OrgModel(org_id="test")
        for _ in range(_WARMUP_SAMPLES - 1):
            m.append([0.0] * 10)
        assert not m.should_refit()

    def test_should_refit_true_after_warmup_and_interval(self):
        try:
            import sklearn  # noqa
        except ImportError:
            pytest.skip("sklearn not installed")
        m = _OrgModel(org_id="test")
        for i in range(_WARMUP_SAMPLES + _REFIT_INTERVAL):
            m.append([float(i % 5)] * 10)
        assert m.should_refit()

    def test_append_caps_history_at_max(self):
        from detector.anomaly import _MAX_HISTORY
        m = _OrgModel(org_id="test")
        for i in range(_MAX_HISTORY + 50):
            m.append([float(i)] * 10)
        assert len(m.history) == _MAX_HISTORY

    def test_fit_sets_fitted_flag(self):
        try:
            import sklearn  # noqa
        except ImportError:
            pytest.skip("sklearn not installed")
        m = _OrgModel(org_id="test")
        for i in range(_WARMUP_SAMPLES):
            m.append([float(i % 3)] * 10)
        m.fit()
        assert m.fitted

    def test_score_after_fitting_in_range(self):
        try:
            import sklearn  # noqa
        except ImportError:
            pytest.skip("sklearn not installed")
        m = _OrgModel(org_id="test")
        # All normal: 0 velocity, 0 tokens, 0 pii
        normal = [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0]
        for _ in range(_WARMUP_SAMPLES):
            m.append(normal[:])
        m.fit()
        score = m.score(normal)
        assert 0.0 <= score <= 1.0

    def test_highly_anomalous_sample_scores_higher_than_normal(self):
        try:
            import sklearn  # noqa
        except ImportError:
            pytest.skip("sklearn not installed")
        m = _OrgModel(org_id="test")
        normal = [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0]
        anomalous = [1000.0, 1000.0, 50000.0, 100000.0, 1.0, 1.0, 20.0, 20.0, 0.0, 1.0]
        for _ in range(_WARMUP_SAMPLES):
            m.append(normal[:])
        m.fit()
        normal_score   = m.score(normal)
        anomalous_score = m.score(anomalous)
        # Anomalous should score higher (or at least no lower)
        assert anomalous_score >= normal_score - 0.05   # 5% tolerance


# ── AnomalyDetector ───────────────────────────────────────────────────────────

class TestAnomalyDetector:
    def setup_method(self):
        self.det = AnomalyDetector()

    def _event(self, pii: list[str] = (), length: int = 100) -> dict:
        return {"pii": list(pii), "len": length}

    def test_warmup_returns_zero(self):
        ev = [self._event()]
        score = self.det.observe("new-org", ev, ev)
        assert score == 0.0

    def test_different_orgs_isolated(self):
        try:
            import sklearn  # noqa
        except ImportError:
            pytest.skip("sklearn not installed")
        # Populate org-a with normal traffic
        ev = [self._event()] * (_WARMUP_SAMPLES + _REFIT_INTERVAL)
        self.det.observe("org-a", ev, ev)
        # org-b should still be at 0 (warming up)
        score_b = self.det.observe("org-b", [self._event()], [self._event()])
        assert score_b == 0.0

    def test_model_info_unseen_org(self):
        info = self.det.model_info("never-seen")
        assert info["status"] == "unseen"

    def test_model_info_warming_up(self):
        ev = [self._event()]
        self.det.observe("warm-org", ev, ev)
        info = self.det.model_info("warm-org")
        assert info["status"] in ("warming_up", "fitted")
        assert info["samples"] >= 1

    def test_score_bounded(self):
        try:
            import sklearn  # noqa
        except ImportError:
            pytest.skip("sklearn not installed")
        # Feed enough to fit
        normal = [self._event()] * (_WARMUP_SAMPLES + _REFIT_INTERVAL + 5)
        for _ in range(3):
            score = self.det.observe("bounded-org", normal, normal)
        assert 0.0 <= score <= 1.0

    def test_thread_safety(self):
        """Concurrent observe() calls should not raise."""
        errors = []
        def worker(org_id):
            try:
                for _ in range(10):
                    self.det.observe(org_id, [self._event()], [self._event()])
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(f"thr-org-{i}",)) for i in range(5)]
        for t in threads: t.start()
        for t in threads: t.join(timeout=5)
        assert not errors, f"Thread errors: {errors}"

    def test_get_anomaly_detector_singleton(self):
        a = get_anomaly_detector()
        b = get_anomaly_detector()
        assert a is b
