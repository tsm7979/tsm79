"""
CorrelationEngine — deduplication and pattern detection for TSM findings.

Prevents alert fatigue by grouping repeated identical detections within a
configurable time window. Elevates risk when suspicious patterns emerge
(e.g., the same org sending PII-containing prompts repeatedly).

Adapted from SecOps-ai CorrelationEngine pattern.
"""
from __future__ import annotations

import hashlib
import time
from collections import defaultdict
from dataclasses import dataclass, field
from threading import Lock


@dataclass
class CorrelatedEvent:
    fingerprint:   str
    pii_types:     list[str]
    org_id:        str
    first_seen:    float        # Unix timestamp
    last_seen:     float
    count:         int
    risk_score:    float
    elevated_risk: float        # risk after correlation multiplier


class CorrelationEngine:
    """
    Deduplicate and correlate detection events.

    Events with the same (org_id, frozenset(pii_types)) fingerprint within
    `dedup_window_seconds` are grouped. If count exceeds `alert_threshold`,
    the risk score is multiplied by `risk_multiplier`.

    Thread-safe.
    """

    def __init__(
        self,
        dedup_window_seconds: int = 3600,   # 1 hour dedup window
        alert_threshold: int = 3,           # 3 similar events → elevate risk
        risk_multiplier: float = 1.25,      # 25% risk increase on correlated burst
    ) -> None:
        self._window = dedup_window_seconds
        self._threshold = alert_threshold
        self._multiplier = risk_multiplier
        self._events: dict[str, CorrelatedEvent] = {}
        self._org_counters: dict[str, list[float]] = defaultdict(list)
        self._lock = Lock()

    def process(
        self,
        org_id:    str,
        pii_types: list[str],
        risk_score: float,
    ) -> tuple[bool, float, int]:
        """
        Record an event and return whether it is a duplicate, the (possibly elevated)
        risk score, and the correlation count.

        Returns:
            (is_duplicate, adjusted_risk_score, occurrence_count)
        """
        fingerprint = _fingerprint(org_id, pii_types)
        now = time.time()

        with self._lock:
            self._evict_stale(now)

            event = self._events.get(fingerprint)
            if event:
                event.last_seen = now
                event.count += 1
                event.risk_score = max(event.risk_score, risk_score)

                if event.count >= self._threshold:
                    event.elevated_risk = min(100.0, event.risk_score * self._multiplier)
                else:
                    event.elevated_risk = event.risk_score

                return True, event.elevated_risk, event.count
            else:
                self._events[fingerprint] = CorrelatedEvent(
                    fingerprint=fingerprint,
                    pii_types=pii_types,
                    org_id=org_id,
                    first_seen=now,
                    last_seen=now,
                    count=1,
                    risk_score=risk_score,
                    elevated_risk=risk_score,
                )
                return False, risk_score, 1

    def stats(self) -> dict:
        """Return a snapshot of active correlation buckets for the health endpoint."""
        with self._lock:
            now = time.time()
            active = {k: v for k, v in self._events.items() if now - v.last_seen < self._window}
            return {
                "active_buckets": len(active),
                "total_orgs": len({e.org_id for e in active.values()}),
            }

    def _evict_stale(self, now: float) -> None:
        """Remove events outside the dedup window. Must be called with lock held."""
        cutoff = now - self._window
        stale = [k for k, v in self._events.items() if v.last_seen < cutoff]
        for k in stale:
            del self._events[k]


def _fingerprint(org_id: str, pii_types: list[str]) -> str:
    key = f"{org_id}:{':'.join(sorted(pii_types))}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


# Module-level singleton — shared across all requests in the detector process
_engine = CorrelationEngine()


def correlate(org_id: str, pii_types: list[str], risk_score: float) -> tuple[bool, float, int]:
    return _engine.process(org_id, pii_types, risk_score)


def correlation_stats() -> dict:
    return _engine.stats()
