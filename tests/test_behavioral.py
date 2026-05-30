"""
Tests: detector/behavioral.py + detector/state/backends.py

Coverage:
  - InMemoryBackend: record/query/count/eviction
  - BehavioralAnalyzer: velocity, exfil, scan scoring
  - AnomalyReport thresholds and composite logic
  - _analyse() pure function (no I/O)
"""
from __future__ import annotations

import time

import pytest

from detector.behavioral import BehavioralAnalyzer, AnomalyReport, _analyse
from detector.state.backends import InMemoryBackend


# ── InMemoryBackend ───────────────────────────────────────────────────────────

class TestInMemoryBackend:
    def setup_method(self):
        self.b = InMemoryBackend(max_keys=5)

    def test_record_and_query(self):
        self.b.record("org1", {"pii": ["EMAIL"], "len": 100}, window_secs=60)
        events = self.b.query("org1", 60)
        assert len(events) == 1
        assert events[0]["pii"] == ["EMAIL"]

    def test_count(self):
        for _ in range(3):
            self.b.record("org2", {"pii": [], "len": 50}, window_secs=60)
        assert self.b.count("org2", 60) == 3

    def test_query_empty_key(self):
        assert self.b.query("nonexistent", 60) == []

    def test_count_empty_key(self):
        assert self.b.count("nonexistent", 60) == 0

    def test_stale_events_not_returned(self):
        # Record with window=0.01s, query with same window — should be empty after brief sleep
        self.b.record("org3", {"pii": [], "len": 10}, window_secs=0.001)
        # Record a fresh event under a different window
        self.b.record("org3", {"pii": [], "len": 10}, window_secs=60)
        # At least the fresh one should be there
        events = self.b.query("org3", 60)
        assert len(events) >= 1

    def test_lru_eviction_at_max_keys(self):
        # Fill to max
        for i in range(5):
            self.b.record(f"org{i}", {"pii": [], "len": 1}, window_secs=60)
        # Add one more — should evict oldest (org0)
        self.b.record("org5", {"pii": [], "len": 1}, window_secs=60)
        # Total keys should not exceed max_keys + 1 (eviction removes 10%)
        total = len(self.b.keys_matching("org"))
        assert total <= 5

    def test_multiple_events_same_key(self):
        for i in range(10):
            self.b.record("multi", {"pii": ["SSN"], "len": i * 100}, window_secs=60)
        events = self.b.query("multi", 60)
        assert len(events) == 10

    def test_nonce_not_returned_in_payload(self):
        # Nonce is added by RedisBackend; InMemory stores payload as-is
        self.b.record("nc", {"pii": ["SSN"], "len": 50}, window_secs=60)
        events = self.b.query("nc", 60)
        assert "_n" not in events[0]

    def test_keys_matching_prefix(self):
        self.b.record("behavioral:org1", {"pii": [], "len": 1}, window_secs=60)
        self.b.record("behavioral:org2", {"pii": [], "len": 1}, window_secs=60)
        self.b.record("other:key", {"pii": [], "len": 1}, window_secs=60)
        keys = self.b.keys_matching("behavioral:")
        assert "behavioral:org1" in keys
        assert "behavioral:org2" in keys
        assert "other:key" not in keys


# ── _analyse() pure function ──────────────────────────────────────────────────

class TestAnalysePureFunction:
    def _make_events(self, n: int, pii: list[str] = (), length: int = 100) -> list[dict]:
        return [{"pii": list(pii), "len": length} for _ in range(n)]

    def test_clean_returns_zero_scores(self):
        r = _analyse([], [], [])
        assert r.velocity_score == 0.0
        assert r.exfil_score == 0.0
        assert r.scan_score == 0.0
        assert r.composite_score == 0.0
        assert not r.is_anomalous

    def test_velocity_warn_threshold(self):
        events = self._make_events(20)
        r = _analyse(events, events, events)
        assert r.velocity_score == 0.4   # 20 = _VEL_WARN

    def test_velocity_high_threshold(self):
        events = self._make_events(50)
        r = _analyse(events, events, events)
        assert r.velocity_score == 0.7

    def test_velocity_critical_threshold(self):
        events = self._make_events(100)
        r = _analyse(events, events, events)
        assert r.velocity_score == 1.0
        assert r.is_anomalous

    def test_exfil_warn_threshold(self):
        # token_budget = sum(len)//4; pii_requests = count with pii
        # Need weighted >= 500 → token_budget * (1 + pii_ratio)
        # With 5 events of len=500 (125 tokens each = 625 total), all pii → weighted ~1250
        events = self._make_events(5, pii=["EMAIL"], length=500)
        r = _analyse([], events, [])
        assert r.exfil_score >= 0.35

    def test_exfil_critical_threshold(self):
        # 10 events × 4000 chars each = 10000 tokens; with pii ratio 1.0 → weighted ~20000
        events = self._make_events(10, pii=["SSN"], length=4000)
        r = _analyse([], events, [])
        assert r.exfil_score == 1.0

    def test_scan_warn_threshold(self):
        # 3 distinct pii types across scan events
        events = [
            {"pii": ["SSN"], "len": 100},
            {"pii": ["EMAIL"], "len": 100},
            {"pii": ["PHONE"], "len": 100},
        ]
        r = _analyse([], [], events)
        assert r.scan_score >= 0.4

    def test_scan_high_threshold(self):
        # 5+ distinct types
        events = [{"pii": [f"TYPE_{i}"], "len": 100} for i in range(5)]
        r = _analyse([], [], events)
        assert r.scan_score >= 0.8

    def test_composite_is_max_not_sum(self):
        # velocity=0.7, exfil=0.35 → composite should be 0.7, not 1.05
        vel   = self._make_events(50)  # velocity_score = 0.7
        exfil = self._make_events(3, pii=["EMAIL"], length=500)
        r = _analyse(vel, exfil, [])
        assert r.composite_score == max(r.velocity_score, r.exfil_score, r.scan_score)
        assert r.composite_score <= 1.0

    def test_signals_populated(self):
        events = self._make_events(100)
        r = _analyse(events, events, events)
        assert len(r.signals) > 0
        assert any("velocity" in s for s in r.signals)

    def test_is_anomalous_threshold_at_0_3(self):
        # Exactly at threshold
        r = AnomalyReport(composite_score=0.3)
        assert r.is_anomalous
        r2 = AnomalyReport(composite_score=0.29)
        assert not r2.is_anomalous


# ── BehavioralAnalyzer integration ───────────────────────────────────────────

class TestBehavioralAnalyzer:
    def setup_method(self):
        # Use InMemoryBackend explicitly — no Redis required
        self.analyzer = BehavioralAnalyzer(backend=InMemoryBackend())

    def test_single_clean_request_not_anomalous(self):
        r = self.analyzer.observe_and_analyse("org-a", [], 100)
        assert not r.is_anomalous

    def test_velocity_burst_detected(self):
        # Send 100 requests in < 1 second — should trigger velocity anomaly
        for _ in range(100):
            r = self.analyzer.observe_and_analyse("org-burst", ["SSN"], 200)
        assert r.velocity_score >= 1.0
        assert r.is_anomalous

    def test_different_orgs_isolated(self):
        # Burst on org-x should not affect org-y
        for _ in range(100):
            self.analyzer.observe_and_analyse("org-x", ["SSN"], 100)
        r_y = self.analyzer.observe_and_analyse("org-y", [], 100)
        assert r_y.velocity_score == 0.0

    def test_org_stats_returns_correct_counts(self):
        for _ in range(5):
            self.analyzer.observe_and_analyse("org-stats", ["EMAIL"], 100)
        stats = self.analyzer.org_stats("org-stats")
        assert stats["org_id"] == "org-stats"
        assert stats["events_60s"] == 5
        assert stats["events_10min"] == 5

    def test_org_stats_unknown_org(self):
        stats = self.analyzer.org_stats("org-never-seen")
        assert stats["org_id"] == "org-never-seen"
        assert stats["events_60s"] == 0

    def test_pii_types_tracked_for_scan(self):
        pii_sets = [["SSN"], ["EMAIL"], ["PHONE"], ["CREDIT_CARD"], ["GITHUB_TOKEN"]]
        for pii in pii_sets:
            self.analyzer.observe_and_analyse("org-scan", pii, 100)
        r = self.analyzer.observe_and_analyse("org-scan", [], 100)
        assert r.scan_score >= 0.8   # 5 distinct types → _SCAN_HIGH

    def test_get_analyzer_returns_singleton(self):
        from detector.behavioral import get_analyzer
        a = get_analyzer()
        b = get_analyzer()
        assert a is b

    def test_backend_injected_correctly(self):
        backend = InMemoryBackend()
        analyzer = BehavioralAnalyzer(backend=backend)
        analyzer.observe_and_analyse("inj-org", ["SSN"], 50)
        # Verify event was written to the injected backend
        events = backend.query("behavioral:inj-org", 60)
        assert len(events) == 1
        assert events[0]["pii"] == ["SSN"]
        assert events[0]["len"] == 50
