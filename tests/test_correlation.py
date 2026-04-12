"""
Tests: detector/correlation.py — CorrelationEngine

Coverage:
  - _fingerprint: deterministic, sorted pii_types, 16-char hex
  - CorrelationEngine (memory mode):
      - first occurrence: not duplicate, score unchanged, count=1
      - repeat within window: is_duplicate=True, count increments
      - risk elevation at threshold (3rd occurrence)
      - risk cap at 100.0
      - eviction after dedup window expires
      - different orgs don't interfere
      - pii_types order-invariant fingerprint
      - stats() returns active_buckets
      - thread safety under concurrent process() calls
  - CorrelationEngine (Redis mode via mock):
      - first occurrence stored as new hash
      - repeat increments count and elevates risk at threshold
      - Redis failure falls back gracefully (returns original score, count=1)
  - Module-level correlate() and correlation_stats()
"""
from __future__ import annotations

import threading
import time
from unittest.mock import MagicMock, patch

import pytest

from detector.correlation import (
    CorrelationEngine,
    CorrelatedEvent,
    _fingerprint,
    correlate,
    correlation_stats,
)


# ── _fingerprint ──────────────────────────────────────────────────────────────

class TestFingerprint:
    def test_returns_16_hex_chars(self):
        fp = _fingerprint("org1", ["SSN"])
        assert len(fp) == 16
        assert all(c in "0123456789abcdef" for c in fp)

    def test_deterministic(self):
        a = _fingerprint("org1", ["SSN", "EMAIL"])
        b = _fingerprint("org1", ["SSN", "EMAIL"])
        assert a == b

    def test_order_invariant(self):
        a = _fingerprint("org1", ["SSN", "EMAIL"])
        b = _fingerprint("org1", ["EMAIL", "SSN"])
        assert a == b

    def test_different_orgs_different_fp(self):
        a = _fingerprint("org-a", ["SSN"])
        b = _fingerprint("org-b", ["SSN"])
        assert a != b

    def test_different_pii_different_fp(self):
        a = _fingerprint("org1", ["SSN"])
        b = _fingerprint("org1", ["EMAIL"])
        assert a != b

    def test_empty_pii_stable(self):
        fp = _fingerprint("org1", [])
        assert len(fp) == 16


# ── CorrelationEngine (memory mode) ───────────────────────────────────────────

class TestCorrelationEngineMemory:
    def _engine(self, window=3600, threshold=3, multiplier=1.25):
        return CorrelationEngine(
            dedup_window_seconds=window,
            alert_threshold=threshold,
            risk_multiplier=multiplier,
        )

    def test_first_occurrence_not_duplicate(self):
        eng = self._engine()
        is_dup, score, count = eng.process("org1", ["SSN"], 50.0)
        assert not is_dup
        assert score == pytest.approx(50.0)
        assert count == 1

    def test_second_occurrence_is_duplicate(self):
        eng = self._engine()
        eng.process("org1", ["SSN"], 50.0)
        is_dup, score, count = eng.process("org1", ["SSN"], 50.0)
        assert is_dup
        assert count == 2

    def test_below_threshold_score_unchanged(self):
        eng = self._engine(threshold=3)
        eng.process("org1", ["SSN"], 50.0)
        _, score, count = eng.process("org1", ["SSN"], 50.0)
        # count=2, threshold=3 → no elevation
        assert score == pytest.approx(50.0)
        assert count == 2

    def test_risk_elevated_at_threshold(self):
        eng = self._engine(threshold=3, multiplier=1.25)
        eng.process("org1", ["SSN"], 80.0)
        eng.process("org1", ["SSN"], 80.0)
        _, score, count = eng.process("org1", ["SSN"], 80.0)
        # count=3 ≥ threshold → 80 * 1.25 = 100.0
        assert count == 3
        assert score == pytest.approx(min(100.0, 80.0 * 1.25))

    def test_risk_capped_at_100(self):
        eng = self._engine(threshold=2, multiplier=2.0)
        eng.process("org1", ["SSN"], 90.0)
        _, score, count = eng.process("org1", ["SSN"], 90.0)
        # 90 * 2.0 = 180, capped at 100
        assert score == pytest.approx(100.0)

    def test_count_increments_beyond_threshold(self):
        eng = self._engine(threshold=2)
        for i in range(5):
            _, _, count = eng.process("org1", ["EMAIL"], 40.0)
        assert count == 5

    def test_different_orgs_isolated(self):
        eng = self._engine()
        for _ in range(3):
            eng.process("org-a", ["SSN"], 80.0)
        # org-b should start fresh
        is_dup, score, count = eng.process("org-b", ["SSN"], 80.0)
        assert not is_dup
        assert count == 1

    def test_pii_order_invariant(self):
        eng = self._engine()
        eng.process("org1", ["SSN", "EMAIL"], 60.0)
        # Same fingerprint regardless of order
        is_dup, _, _ = eng.process("org1", ["EMAIL", "SSN"], 60.0)
        assert is_dup

    def test_different_pii_types_separate_buckets(self):
        eng = self._engine()
        eng.process("org1", ["SSN"], 50.0)
        # Different pii_types → different bucket, not a duplicate
        is_dup, _, count = eng.process("org1", ["EMAIL"], 50.0)
        assert not is_dup
        assert count == 1

    def test_eviction_after_window(self):
        # Use a very short window so entries expire quickly
        eng = self._engine(window=0)  # window=0 → anything older than now is stale
        eng.process("org1", ["SSN"], 50.0)
        # Force a tiny sleep so last_seen is strictly < cutoff (now - 0 = now)
        time.sleep(0.01)
        # The next call triggers eviction; stale entry removed
        is_dup, _, count = eng.process("org1", ["SSN"], 50.0)
        # After eviction, org1:SSN is new again
        assert not is_dup
        assert count == 1

    def test_stats_active_buckets(self):
        eng = self._engine()
        eng.process("org-s1", ["SSN"], 50.0)
        eng.process("org-s2", ["EMAIL"], 50.0)
        st = eng.stats()
        assert st["active_buckets"] >= 2
        assert st["backend"] == "memory"

    def test_stats_empty_engine(self):
        eng = self._engine()
        st = eng.stats()
        assert st["active_buckets"] == 0

    def test_thread_safety(self):
        eng = self._engine()
        errors = []

        def worker(org_id):
            try:
                for _ in range(20):
                    eng.process(org_id, ["SSN"], 50.0)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(f"org-{i}",)) for i in range(8)]
        for t in threads: t.start()
        for t in threads: t.join(timeout=5)
        assert not errors, f"Thread errors: {errors}"

    def test_concurrent_same_org_count_consistent(self):
        """Concurrent writes to same org must not lose increments."""
        eng = self._engine()
        n = 50
        results = []
        lock = threading.Lock()

        def worker():
            _, _, count = eng.process("shared-org", ["SSN"], 50.0)
            with lock:
                results.append(count)

        threads = [threading.Thread(target=worker) for _ in range(n)]
        for t in threads: t.start()
        for t in threads: t.join(timeout=5)
        # Final count must equal number of calls
        assert max(results) == n


# ── CorrelationEngine (Redis mode via mock) ───────────────────────────────────

class TestCorrelationEngineRedis:
    """
    Tests for the Redis backend path.  We never connect to a real Redis;
    the redis client is replaced with a MagicMock.
    """

    def _make_engine_with_mock_redis(self) -> tuple[CorrelationEngine, MagicMock]:
        """Return (engine, mock_redis) in Redis mode without touching a real server."""
        eng = CorrelationEngine.__new__(CorrelationEngine)
        eng._window     = 3600
        eng._threshold  = 3
        eng._multiplier = 1.25
        eng._mode       = "redis"

        mock_redis = MagicMock()
        eng._redis = mock_redis
        return eng, mock_redis

    def _make_pipeline(self, mock_redis):
        pipe = MagicMock()
        mock_redis.pipeline.return_value = pipe
        pipe.hset.return_value = pipe
        pipe.expire.return_value = pipe
        pipe.execute.return_value = [1, True]
        return pipe

    def test_first_occurrence_new_hash(self):
        eng, mock_redis = self._make_engine_with_mock_redis()
        mock_redis.hgetall.return_value = {}   # nothing stored yet
        self._make_pipeline(mock_redis)

        is_dup, score, count = eng.process("org1", ["SSN"], 60.0)
        assert not is_dup
        assert score == pytest.approx(60.0)
        assert count == 1

    def test_repeat_occurrence_increments_count(self):
        eng, mock_redis = self._make_engine_with_mock_redis()
        now = time.time()
        # Simulate existing entry with count=2, within window
        mock_redis.hgetall.return_value = {
            "org_id": "org1",
            "pii": '["SSN"]',
            "first_seen": str(now - 10),
            "last_seen": str(now - 1),
            "count": "2",
            "peak_risk": "60.0",
        }
        self._make_pipeline(mock_redis)

        is_dup, score, count = eng.process("org1", ["SSN"], 60.0)
        assert is_dup
        assert count == 3
        # count=3 ≥ threshold=3 → 60 * 1.25 = 75
        assert score == pytest.approx(75.0)

    def test_expired_entry_treated_as_new(self):
        eng, mock_redis = self._make_engine_with_mock_redis()
        very_old = time.time() - eng._window - 100
        mock_redis.hgetall.return_value = {
            "count": "5",
            "peak_risk": "70.0",
            "last_seen": str(very_old),
        }
        self._make_pipeline(mock_redis)

        is_dup, score, count = eng.process("org1", ["SSN"], 70.0)
        # last_seen > window → treated as new
        assert not is_dup
        assert count == 1

    def test_redis_error_on_hgetall_falls_back(self):
        import redis as _redis_module
        eng, mock_redis = self._make_engine_with_mock_redis()
        mock_redis.hgetall.side_effect = _redis_module.RedisError("timeout")

        is_dup, score, count = eng.process("org1", ["SSN"], 70.0)
        assert not is_dup
        assert score == pytest.approx(70.0)
        assert count == 1

    def test_redis_error_on_pipeline_falls_back(self):
        import redis as _redis_module
        eng, mock_redis = self._make_engine_with_mock_redis()
        mock_redis.hgetall.return_value = {}
        pipe = MagicMock()
        mock_redis.pipeline.return_value = pipe
        pipe.execute.side_effect = _redis_module.RedisError("READONLY")

        is_dup, score, count = eng.process("org1", ["SSN"], 70.0)
        assert not is_dup
        assert score == pytest.approx(70.0)
        assert count == 1

    def test_redis_stats_returns_bucket_count(self):
        eng, mock_redis = self._make_engine_with_mock_redis()
        mock_redis.scan.return_value = (0, ["tsm:corr:abc", "tsm:corr:def"])
        st = eng.stats()
        assert st["active_buckets"] == 2
        assert st["backend"] == "redis"

    def test_redis_stats_error_returns_minus_one(self):
        import redis as _redis_module
        eng, mock_redis = self._make_engine_with_mock_redis()
        mock_redis.scan.side_effect = _redis_module.RedisError("down")
        st = eng.stats()
        assert st["active_buckets"] == -1
        assert st["backend"] == "redis_error"


# ── Module-level convenience functions ───────────────────────────────────────

class TestModuleFunctions:
    def test_correlate_returns_tuple(self):
        result = correlate("fn-org", ["SSN"], 55.0)
        assert isinstance(result, tuple)
        assert len(result) == 3
        is_dup, score, count = result
        assert isinstance(is_dup, bool)
        assert isinstance(score, float)
        assert isinstance(count, int)

    def test_correlation_stats_returns_dict(self):
        st = correlation_stats()
        assert isinstance(st, dict)
        assert "active_buckets" in st
        assert "backend" in st

    def test_correlate_count_increases_on_repeat(self):
        # Use a unique org to avoid interference from other tests
        _, _, c1 = correlate("unique-fn-org-xyz", ["PHONE"], 30.0)
        _, _, c2 = correlate("unique-fn-org-xyz", ["PHONE"], 30.0)
        assert c2 == c1 + 1
