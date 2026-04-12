"""
CorrelationEngine — distributed deduplication and pattern correlation.

Backends (auto-selected):
  InMemoryBackend — single process (default)
  RedisBackend    — multi-pod shared state (set REDIS_URL)

Redis model: hash keyed by "tsm:corr:{fingerprint}" with fields:
  org_id, pii, first_seen, last_seen, count, peak_risk
  EXPIRE = dedup_window + 60s
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import threading
import time
from dataclasses import dataclass


@dataclass
class CorrelatedEvent:
    fingerprint: str
    pii_types:   list[str]
    org_id:      str
    first_seen:  float
    last_seen:   float
    count:       int
    risk_score:  float
    elevated_risk: float


class CorrelationEngine:
    """
    Groups repeated (org_id, pii_types) pairs within a dedup window.
    When an org sends the same PII fingerprint ≥ threshold times, risk is
    multiplied by risk_multiplier (default: +25%).

    Thread-safe and pod-safe (Redis backend shares state across replicas).
    """

    def __init__(
        self,
        dedup_window_seconds: int   = 3600,
        alert_threshold:      int   = 3,
        risk_multiplier:      float = 1.25,
    ) -> None:
        self._window     = dedup_window_seconds
        self._threshold  = alert_threshold
        self._multiplier = risk_multiplier

        url = os.environ.get("REDIS_URL", "").strip()
        if url:
            try:
                import redis as _redis
                r = _redis.from_url(url, decode_responses=True, socket_connect_timeout=2)
                r.ping()
                self._redis = r
                self._mode  = "redis"
                return
            except Exception as exc:
                print(f"[TSM] WARN: Correlation Redis unavailable ({exc!r}) — in-memory.", file=sys.stderr)

        self._redis = None
        self._mode  = "memory"
        self._mem: dict[str, CorrelatedEvent] = {}
        self._lock  = threading.Lock()

    # ── Public API ────────────────────────────────────────────────────────────

    def process(
        self,
        org_id:     str,
        pii_types:  list[str],
        risk_score: float,
    ) -> tuple[bool, float, int]:
        """
        Returns (is_duplicate, adjusted_risk_score, occurrence_count).
        adjusted_risk_score is elevated once count ≥ alert_threshold.
        """
        fp = _fingerprint(org_id, pii_types)
        if self._mode == "redis":
            return self._redis_process(fp, org_id, pii_types, risk_score)
        return self._mem_process(fp, org_id, pii_types, risk_score)

    def stats(self) -> dict:
        if self._mode == "redis":
            return self._redis_stats()
        with self._lock:
            now    = time.time()
            active = {k: v for k, v in self._mem.items() if now - v.last_seen < self._window}
            return {"active_buckets": len(active), "total_orgs": len({e.org_id for e in active.values()}), "backend": "memory"}

    # ── In-memory impl ────────────────────────────────────────────────────────

    def _mem_process(self, fp: str, org_id: str, pii_types: list[str], risk_score: float) -> tuple[bool, float, int]:
        now = time.time()
        with self._lock:
            self._mem_evict(now)
            ev = self._mem.get(fp)
            if ev:
                ev.last_seen  = now
                ev.count     += 1
                ev.risk_score = max(ev.risk_score, risk_score)
                ev.elevated_risk = (
                    min(100.0, ev.risk_score * self._multiplier)
                    if ev.count >= self._threshold
                    else ev.risk_score
                )
                return True, ev.elevated_risk, ev.count
            self._mem[fp] = CorrelatedEvent(
                fingerprint=fp, pii_types=pii_types, org_id=org_id,
                first_seen=now, last_seen=now, count=1,
                risk_score=risk_score, elevated_risk=risk_score,
            )
            return False, risk_score, 1

    def _mem_evict(self, now: float) -> None:
        cutoff = now - self._window
        stale  = [k for k, v in self._mem.items() if v.last_seen < cutoff]
        for k in stale:
            del self._mem[k]

    # ── Redis impl ────────────────────────────────────────────────────────────

    def _rkey(self, fp: str) -> str:
        return f"tsm:corr:{fp}"

    def _redis_process(self, fp: str, org_id: str, pii_types: list[str], risk_score: float) -> tuple[bool, float, int]:
        import redis as _redis
        now = time.time()
        k   = self._rkey(fp)
        try:
            existing = self._redis.hgetall(k)
        except _redis.RedisError:
            return False, risk_score, 1

        # Check window validity
        if existing and (now - float(existing.get("last_seen", 0))) > self._window:
            existing = {}

        try:
            if existing:
                count      = int(existing.get("count", 0)) + 1
                peak_risk  = max(float(existing.get("peak_risk", 0)), risk_score)
                elevated   = (
                    min(100.0, peak_risk * self._multiplier)
                    if count >= self._threshold
                    else peak_risk
                )
                pipe = self._redis.pipeline()
                pipe.hset(k, mapping={"last_seen": now, "count": count, "peak_risk": peak_risk})
                pipe.expire(k, self._window + 60)
                pipe.execute()
                return True, elevated, count
            else:
                pipe = self._redis.pipeline()
                pipe.hset(k, mapping={
                    "org_id": org_id, "pii": json.dumps(pii_types),
                    "first_seen": now, "last_seen": now,
                    "count": 1, "peak_risk": risk_score,
                })
                pipe.expire(k, self._window + 60)
                pipe.execute()
                return False, risk_score, 1
        except _redis.RedisError:
            return False, risk_score, 1

    def _redis_stats(self) -> dict:
        import redis as _redis
        try:
            cursor, keys = 0, []
            while True:
                cursor, batch = self._redis.scan(cursor, match="tsm:corr:*", count=200)
                keys.extend(batch)
                if cursor == 0:
                    break
            return {"active_buckets": len(keys), "backend": "redis"}
        except _redis.RedisError:
            return {"active_buckets": -1, "backend": "redis_error"}


def _fingerprint(org_id: str, pii_types: list[str]) -> str:
    key = f"{org_id}:{':'.join(sorted(pii_types))}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


# ── Module-level singleton ────────────────────────────────────────────────────

_engine = CorrelationEngine()


def correlate(org_id: str, pii_types: list[str], risk_score: float) -> tuple[bool, float, int]:
    return _engine.process(org_id, pii_types, risk_score)


def correlation_stats() -> dict:
    return _engine.stats()
