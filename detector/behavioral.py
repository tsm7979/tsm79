"""
Behavioral analysis — velocity, exfiltration, and category-scan anomaly detection.

Analyses per-org request patterns over time to catch threats invisible to
single-request classifiers:

  1. Velocity limiting        — bursts of requests from one org
  2. Progressive exfiltration — gradual token accumulation across requests
  3. Category scanning        — systematic probing across PII categories

Each dimension returns a score ∈ [0.0, 1.0].  The composite is max() of all
three (not sum — avoids double-counting correlated signals).

Backend selection (auto, no code change needed):
  - InMemoryBackend  : default, process-local, zero deps
  - RedisBackend     : set REDIS_URL env var → state shared across all pods

Redis data model: sorted set keyed by "behavioral:{org_id}", score = Unix
timestamp, member = JSON event payload.  Eviction is implicit (ZREMRANGEBYSCORE
on every write) so memory is bounded without a background sweeper.
"""
from __future__ import annotations

import os
import threading
from dataclasses import dataclass, field
from typing import Sequence

from detector.state.backends import StateBackend, create_backend

# ── Windows (seconds) ─────────────────────────────────────────────────────────

_VEL_WIN   = 60.0    # velocity: 1-minute window
_EXFIL_WIN = 600.0   # exfiltration: 10-minute window
_SCAN_WIN  = 300.0   # category scan: 5-minute window

# The backend stores all events under a single key with the largest window's
# TTL; we query subsets by passing different window_secs to query().
_MAX_WINDOW = _EXFIL_WIN

# ── Thresholds ────────────────────────────────────────────────────────────────

_VEL_WARN = 20; _VEL_HIGH = 50; _VEL_CRIT = 100   # req / VEL_WIN
_EXFIL_WARN = 500; _EXFIL_HIGH = 2_000; _EXFIL_CRIT = 5_000  # approx tokens
_SCAN_WARN = 3; _SCAN_HIGH = 5   # distinct PII type count / SCAN_WIN


# ── Report ────────────────────────────────────────────────────────────────────

@dataclass
class AnomalyReport:
    velocity_score:  float = 0.0
    exfil_score:     float = 0.0
    scan_score:      float = 0.0
    composite_score: float = 0.0
    signals:         list[str] = field(default_factory=list)

    @property
    def is_anomalous(self) -> bool:
        return self.composite_score >= 0.3


# ── Pure analysis function ────────────────────────────────────────────────────

def _analyse(
    vel_events:   list[dict],
    exfil_events: list[dict],
    scan_events:  list[dict],
) -> AnomalyReport:
    """Pure function: no I/O, no side effects. Safe to test in isolation."""
    report = AnomalyReport()

    # 1. Velocity ──────────────────────────────────────────────────────────────
    vc = len(vel_events)
    if vc >= _VEL_CRIT:
        report.velocity_score = 1.0
        report.signals.append(f"velocity:{vc}req/min (critical)")
    elif vc >= _VEL_HIGH:
        report.velocity_score = 0.7
        report.signals.append(f"velocity:{vc}req/min (high)")
    elif vc >= _VEL_WARN:
        report.velocity_score = 0.4
        report.signals.append(f"velocity:{vc}req/min (warn)")

    # 2. Progressive exfiltration ──────────────────────────────────────────────
    # Approximate token count: chars / 4.  Weight up requests that included PII.
    token_budget = sum(e.get("len", 0) for e in exfil_events) // 4
    pii_count    = sum(1 for e in exfil_events if e.get("pii"))
    weighted     = token_budget * (1 + pii_count / max(len(exfil_events), 1))
    if weighted >= _EXFIL_CRIT:
        report.exfil_score = 1.0
        report.signals.append(f"exfiltration:~{token_budget}tok/10min (critical)")
    elif weighted >= _EXFIL_HIGH:
        report.exfil_score = 0.7
        report.signals.append(f"exfiltration:~{token_budget}tok/10min (high)")
    elif weighted >= _EXFIL_WARN:
        report.exfil_score = 0.35
        report.signals.append(f"exfiltration:~{token_budget}tok/10min (warn)")

    # 3. Category scanning ─────────────────────────────────────────────────────
    seen_types: set[str] = set()
    for e in scan_events:
        seen_types.update(e.get("pii", []))
    distinct = len(seen_types)
    if distinct >= _SCAN_HIGH:
        report.scan_score = 0.8
        report.signals.append(f"scan:{distinct} PII types/5min (high)")
    elif distinct >= _SCAN_WARN:
        report.scan_score = 0.4
        report.signals.append(f"scan:{distinct} PII types/5min (warn)")

    report.composite_score = max(
        report.velocity_score, report.exfil_score, report.scan_score
    )
    return report


# ── Analyzer ──────────────────────────────────────────────────────────────────

class BehavioralAnalyzer:
    """
    Distributed-ready per-org behavioral analyzer.

    All state is stored in the injected `backend`:
      - InMemoryBackend (default)  : single-process, no deps
      - RedisBackend (REDIS_URL)   : shared across detector replicas

    Analysis logic lives in _analyse() — a pure function with no I/O.  The
    analyzer is responsible only for reading/writing the backend and calling it.
    """

    def __init__(self, backend: StateBackend | None = None) -> None:
        self._backend = backend or create_backend()

    def observe_and_analyse(
        self,
        org_id:    str,
        pii_types: Sequence[str],
        text_len:  int,
    ) -> AnomalyReport:
        """
        Record this request for `org_id` and return the current anomaly report.
        Thread-safe and pod-safe (state in backend, not local).
        """
        key     = f"behavioral:{org_id}"
        payload = {"pii": list(pii_types), "len": text_len}

        # Record against the widest window; narrower windows query a subset
        self._backend.record(key, payload, window_secs=_MAX_WINDOW, ttl_secs=_MAX_WINDOW + 60)

        vel_events   = self._backend.query(key, _VEL_WIN)
        exfil_events = self._backend.query(key, _EXFIL_WIN)
        scan_events  = self._backend.query(key, _SCAN_WIN)

        return _analyse(vel_events, exfil_events, scan_events)

    def org_stats(self, org_id: str) -> dict:
        """Return live stats for an org (debug / health endpoint)."""
        key = f"behavioral:{org_id}"
        return {
            "org_id":       org_id,
            "events_60s":   self._backend.count(key, _VEL_WIN),
            "events_10min": self._backend.count(key, _EXFIL_WIN),
        }


# ── Module-level singleton ────────────────────────────────────────────────────

_analyzer: BehavioralAnalyzer | None = None
_analyzer_lock = threading.Lock()


def get_analyzer() -> BehavioralAnalyzer:
    global _analyzer
    if _analyzer is None:
        with _analyzer_lock:
            if _analyzer is None:
                _analyzer = BehavioralAnalyzer()
    return _analyzer


# ── Self-test ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    a   = BehavioralAnalyzer()    # uses InMemoryBackend
    org = "test-org"
    for _ in range(60):
        report = a.observe_and_analyse(org, ["SSN", "EMAIL"], 1000)
    print(f"velocity_score = {report.velocity_score:.2f}")
    print(f"exfil_score    = {report.exfil_score:.2f}")
    print(f"scan_score     = {report.scan_score:.2f}")
    print(f"composite      = {report.composite_score:.2f}")
    print(f"signals        = {report.signals}")
    assert report.velocity_score >= 0.7, "Expected high velocity score for 60 req/min"
    print("Behavioral analysis: PASS")
